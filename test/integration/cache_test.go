package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"k8s.io/client-go/kubernetes/scheme"
	"net/http"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Minimal real HTTP persistence endpoint for the proxy's Kubernetes client.
// The integration test writes one record; watches stay open until shutdown.
type cacheAPI struct {
	mu      sync.Mutex
	records map[string]corev1.ConfigMap
}

func (c *cacheAPI) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := "/api/v1/namespaces/proxy/configmaps"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("watch") == "true" {
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		name := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, prefix), "/")
		encode := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		switch r.Method {
		case http.MethodGet:
			if name == "" {
				list := &corev1.ConfigMapList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMapList"}, ListMeta: metav1.ListMeta{ResourceVersion: "1"}, Items: []corev1.ConfigMap{}}
				for _, cm := range c.records {
					list.Items = append(list.Items, cm)
				}
				encode(list)
				return
			}
			if cm, ok := c.records[name]; ok {
				encode(cm)
				return
			}
			w.WriteHeader(404)
			encode(&metav1.Status{Status: "Failure", Reason: metav1.StatusReasonNotFound, Code: 404})
		case http.MethodPost:
			var cm corev1.ConfigMap
			body, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				http.Error(w, readErr.Error(), 400)
				return
			}
			if _, _, err := scheme.Codecs.UniversalDeserializer().Decode(body, nil, &cm); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			cm.ResourceVersion = fmt.Sprint(len(c.records) + 2)
			cm.APIVersion = "v1"
			cm.Kind = "ConfigMap"
			c.records[cm.Name] = cm
			w.WriteHeader(201)
			encode(cm)
		default:
			http.Error(w, "unsupported operation", 405)
		}
	})
}
