package httpapi

import (
	"context"
	"net/http"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func rootfsTarUploadHandler(runtime *grpcRuntime, opt Options) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			w.Header().Set("Allow", http.MethodPut)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		token := strings.TrimPrefix(r.URL.Path, "/v1/rootfs-tar/")
		if token == "" || strings.Contains(token, "/") {
			http.NotFound(w, r)
			return
		}
		if r.ContentLength < 0 {
			http.Error(w, "Content-Length is required", http.StatusLengthRequired)
			return
		}
		rpc := &compatRPCAdapter{options: opt, runtime: runtime}
		ctx, cancel := context.WithTimeout(r.Context(), rootfsTarUploadTTL)
		defer cancel()
		if err := rpc.uploadRootfsTar(ctx, token, r.ContentLength, r.Body); err != nil {
			writeRootfsUploadError(w, err)
			return
		}
		w.WriteHeader(http.StatusCreated)
	})
}

func writeRootfsUploadError(w http.ResponseWriter, err error) {
	code := status.Code(err)
	statusCode := http.StatusInternalServerError
	switch code {
	case codes.InvalidArgument:
		statusCode = http.StatusBadRequest
	case codes.PermissionDenied:
		statusCode = http.StatusForbidden
	case codes.NotFound:
		statusCode = http.StatusNotFound
	case codes.AlreadyExists:
		statusCode = http.StatusConflict
	case codes.FailedPrecondition:
		statusCode = http.StatusPreconditionFailed
	case codes.Unavailable:
		statusCode = http.StatusServiceUnavailable
	case codes.DeadlineExceeded:
		statusCode = http.StatusRequestTimeout
	}
	http.Error(w, status.Convert(err).Message(), statusCode)
}
