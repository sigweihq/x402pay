package types

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUser_CreatedAt(t *testing.T) {
	tests := []struct {
		name      string
		timestamp string
		checkTime func(*testing.T, time.Time)
	}{
		{
			name:      "valid RFC3339 timestamp",
			timestamp: "2024-01-15T10:30:00Z",
			checkTime: func(t *testing.T, parsed time.Time) {
				assert.Equal(t, 2024, parsed.Year())
				assert.Equal(t, time.January, parsed.Month())
				assert.Equal(t, 15, parsed.Day())
			},
		},
		{
			name:      "RFC3339 with timezone",
			timestamp: "2024-01-15T10:30:00-05:00",
			checkTime: func(t *testing.T, parsed time.Time) {
				assert.Equal(t, 2024, parsed.Year())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := time.Parse(time.RFC3339, tt.timestamp)
			require.NoError(t, err)

			user := &User{
				CreatedAt: parsed,
			}

			assert.Equal(t, parsed, user.CreatedAt)
			if tt.checkTime != nil {
				tt.checkTime(t, user.CreatedAt)
			}
		})
	}
}

func TestUser_UpdatedAt(t *testing.T) {
	tests := []struct {
		name      string
		timestamp string
		checkTime func(*testing.T, time.Time)
	}{
		{
			name:      "valid RFC3339 timestamp",
			timestamp: "2024-02-20T15:45:30Z",
			checkTime: func(t *testing.T, parsed time.Time) {
				assert.Equal(t, 2024, parsed.Year())
				assert.Equal(t, time.February, parsed.Month())
				assert.Equal(t, 20, parsed.Day())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := time.Parse(time.RFC3339, tt.timestamp)
			require.NoError(t, err)

			user := &User{
				UpdatedAt: parsed,
			}

			assert.Equal(t, parsed, user.UpdatedAt)
			if tt.checkTime != nil {
				tt.checkTime(t, user.UpdatedAt)
			}
		})
	}
}
