// Copyright Jetstack Ltd. See LICENSE for details.
package subjectaccessreview

import (
	"context"
	"errors"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	v1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	clientazv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

type blockingReviewer struct {
	clientazv1.SubjectAccessReviewInterface
	entered chan context.Context
}

func (r *blockingReviewer) Create(ctx context.Context, _ *v1.SubjectAccessReview, _ metav1.CreateOptions) (*v1.SubjectAccessReview, error) {
	r.entered <- ctx
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestImpersonationReviewUsesRequestCancellation(t *testing.T) {
	for _, before := range []bool{true, false} {
		name := "during review"
		if before {
			name = "before review"
		}
		t.Run(name, func(t *testing.T) {
			client := &blockingReviewer{entered: make(chan context.Context, 1)}
			reviewer, _ := New(client)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
			req.Header.Set("Impersonate-User", "target")
			req.Header.Set("X-Keep", "unchanged")
			original := req.Header.Clone()
			if before {
				cancel()
			}
			done := make(chan error, 1)
			go func() {
				_, err := reviewer.CheckAuthorizedForImpersonation(req, &user.DefaultInfo{Name: "caller"})
				done <- err
			}()
			if !before {
				select {
				case received := <-client.entered:
					if received != ctx {
						t.Fatal("review did not receive the request context")
					}
				case <-time.After(time.Second):
					t.Fatal("review never started")
				}
				cancel()
			}
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("expected cancellation, got %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("canceled review did not return")
			}
			if !reflect.DeepEqual(req.Header, original) {
				t.Fatal("failed review changed request headers")
			}
			if before && len(client.entered) != 0 {
				t.Fatal("canceled request still submitted a review")
			}
		})
	}
}
