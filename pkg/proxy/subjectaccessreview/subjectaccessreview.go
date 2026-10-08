// Copyright Jetstack Ltd. See LICENSE for details.
package subjectaccessreview

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	v1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	clientazv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

var ErrorNoImpersonationUserFound = errors.New("no Impersonation-User header found for request")

// ImpersonationDeniedError distinguishes RBAC denials from API failures.
type ImpersonationDeniedError struct {
	Requester string
	Resource  string
	Name      string
}

func (e *ImpersonationDeniedError) Error() string {
	kind := map[string]string{"users": "user", "groups": "group", "uids": "uid"}[e.Resource]
	if kind != "" {
		return fmt.Sprintf("%s is not allowed to impersonate %s '%s'", e.Requester, kind, e.Name)
	}
	return fmt.Sprintf("%s is not allowed to impersonate extra info '%s'='%s'", e.Requester, strings.TrimPrefix(e.Resource, "userextras/"), e.Name)
}

// IsImpersonationHeader reports whether an HTTP header name is one of the
// Impersonate-* family, matched case insensitively.
func IsImpersonationHeader(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "impersonate-")
}

type SubjectAccessReview struct {
	subjectAccessReviewer clientazv1.SubjectAccessReviewInterface
}

func New(reviewer clientazv1.SubjectAccessReviewInterface) (*SubjectAccessReview, error) {
	return &SubjectAccessReview{subjectAccessReviewer: reviewer}, nil
}

// CheckAuthorizedForImpersonation authorizes each requested identity field.
// Impersonation headers are removed only once every review succeeds.
func (s *SubjectAccessReview) CheckAuthorizedForImpersonation(req *http.Request, requester user.Info) (user.Info, error) {
	target := &user.DefaultInfo{Groups: []string{}, Extra: map[string][]string{}}
	var headersToRemove []string
	for key, values := range req.Header {
		if !IsImpersonationHeader(key) {
			continue
		}
		lower := strings.ToLower(key)
		if req.Header.Get("Impersonate-User") == "" {
			return nil, ErrorNoImpersonationUserFound
		}
		headersToRemove = append(headersToRemove, key)
		first := ""
		if len(values) > 0 {
			first = values[0]
		}
		switch {
		case lower == "impersonate-user":
			if first == "" {
				continue
			}
			if err := s.authorize(req.Context(), "users", first, requester); err != nil {
				return nil, err
			}
			target.Name = first
		case lower == "impersonate-group":
			for _, value := range values {
				if err := s.authorize(req.Context(), "groups", value, requester); err != nil {
					return nil, err
				}
				target.Groups = append(target.Groups, value)
			}
		case lower == "impersonate-uid":
			if err := s.authorize(req.Context(), "uids", first, requester); err != nil {
				return nil, err
			}
			target.UID = first
		case strings.HasPrefix(lower, "impersonate-extra-"):
			name := strings.TrimPrefix(lower, "impersonate-extra-")
			for _, value := range values {
				if err := s.authorize(req.Context(), "userextras/"+name, value, requester); err != nil {
					return nil, err
				}
				target.Extra[name] = append(target.Extra[name], value)
			}
		default:
			return nil, fmt.Errorf("unknown impersonation header '%s'", key)
		}
	}
	if len(headersToRemove) == 0 {
		return nil, nil
	}
	headers := req.Header.Clone()
	for _, key := range headersToRemove {
		delete(headers, key)
	}
	req.Header = headers
	return target, nil
}

func (s *SubjectAccessReview) authorize(ctx context.Context, resource, name string, requester user.Info) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	extras := make(map[string]v1.ExtraValue, len(requester.GetExtra()))
	for key, value := range requester.GetExtra() {
		extras[key] = value
	}
	base, subresource, hasSubresource := strings.Cut(resource, "/")
	group := ""
	if hasSubresource {
		group = "authentication.k8s.io"
	}
	review := &v1.SubjectAccessReview{Spec: v1.SubjectAccessReviewSpec{
		User: requester.GetName(), Groups: requester.GetGroups(), Extra: extras,
		ResourceAttributes: &v1.ResourceAttributes{Verb: "impersonate", Group: group, Resource: base, Subresource: subresource, Name: name},
	}}
	result, err := s.subjectAccessReviewer.Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	if !result.Status.Allowed {
		return &ImpersonationDeniedError{Requester: requester.GetName(), Resource: resource, Name: name}
	}
	return nil
}
