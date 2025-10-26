package utils

import (
	"testing"
)

func TestValidateFacilitatorURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "valid HTTPS URL",
			url:     "https://hub.sigwei.com",
			wantErr: false,
		},
		{
			name:    "valid HTTPS URL with path",
			url:     "https://x402.org/facilitator",
			wantErr: false,
		},
		{
			name:    "invalid HTTP URL",
			url:     "http://hub.sigwei.com",
			wantErr: true,
		},
		{
			name:    "valid localhost for testing",
			url:     "http://localhost:8080",
			wantErr: false,
		},
		{
			name:    "valid 127.0.0.1 for testing",
			url:     "http://127.0.0.1:8080",
			wantErr: false,
		},
		{
			name:    "valid IPv6 localhost for testing",
			url:     "http://[::1]:8080",
			wantErr: false,
		},
		{
			name:    "invalid no protocol",
			url:     "hub.sigwei.com",
			wantErr: true,
		},
		{
			name:    "invalid empty URL",
			url:     "",
			wantErr: true,
		},
		{
			name:    "invalid ftp protocol",
			url:     "ftp://hub.sigwei.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFacilitatorURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFacilitatorURL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
