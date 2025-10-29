package types

import (
	"encoding/json"
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

func TestSupportedResponse_JSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *SupportedResponse
	}{
		{
			name: "parses supported response without extra field",
			input: `{
				"kinds": [
					{
						"x402Version": 1,
						"scheme": "exact",
						"network": "base"
					}
				]
			}`,
			expected: &SupportedResponse{
				Kinds: []NetworkKind{
					{
						X402Version: 1,
						Scheme:      "exact",
						Network:     "base",
						Extra:       nil,
					},
				},
			},
		},
		{
			name: "parses supported response with feePayer in extra field",
			input: `{
				"kinds": [
					{
						"x402Version": 1,
						"scheme": "exact",
						"network": "solana-devnet",
						"extra": {
							"feePayer": "DemoFeePayerAddress123456789"
						}
					}
				]
			}`,
			expected: &SupportedResponse{
				Kinds: []NetworkKind{
					{
						X402Version: 1,
						Scheme:      "exact",
						Network:     "solana-devnet",
						Extra: &NetworkKindExtra{
							FeePayer: "DemoFeePayerAddress123456789",
						},
					},
				},
			},
		},
		{
			name: "parses mixed response with and without extra field",
			input: `{
				"kinds": [
					{
						"x402Version": 1,
						"scheme": "exact",
						"network": "base"
					},
					{
						"x402Version": 1,
						"scheme": "exact",
						"network": "solana-devnet",
						"extra": {
							"feePayer": "SolanaFeePayer456"
						}
					}
				]
			}`,
			expected: &SupportedResponse{
				Kinds: []NetworkKind{
					{
						X402Version: 1,
						Scheme:      "exact",
						Network:     "base",
						Extra:       nil,
					},
					{
						X402Version: 1,
						Scheme:      "exact",
						Network:     "solana-devnet",
						Extra: &NetworkKindExtra{
							FeePayer: "SolanaFeePayer456",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result SupportedResponse
			err := json.Unmarshal([]byte(tt.input), &result)
			require.NoError(t, err)

			assert.Equal(t, len(tt.expected.Kinds), len(result.Kinds))
			for i := range tt.expected.Kinds {
				assert.Equal(t, tt.expected.Kinds[i].X402Version, result.Kinds[i].X402Version)
				assert.Equal(t, tt.expected.Kinds[i].Scheme, result.Kinds[i].Scheme)
				assert.Equal(t, tt.expected.Kinds[i].Network, result.Kinds[i].Network)

				if tt.expected.Kinds[i].Extra == nil {
					assert.Nil(t, result.Kinds[i].Extra)
				} else {
					require.NotNil(t, result.Kinds[i].Extra)
					assert.Equal(t, tt.expected.Kinds[i].Extra.FeePayer, result.Kinds[i].Extra.FeePayer)
				}
			}
		})
	}
}

func TestNetworkKind_JSONMarshal(t *testing.T) {
	tests := []struct {
		name     string
		input    NetworkKind
		expected string
	}{
		{
			name: "marshals without extra field",
			input: NetworkKind{
				X402Version: 1,
				Scheme:      "exact",
				Network:     "base",
			},
			expected: `{"x402Version":1,"scheme":"exact","network":"base"}`,
		},
		{
			name: "marshals with extra field containing feePayer",
			input: NetworkKind{
				X402Version: 1,
				Scheme:      "exact",
				Network:     "solana-devnet",
				Extra: &NetworkKindExtra{
					FeePayer: "TestFeePayer123",
				},
			},
			expected: `{"x402Version":1,"scheme":"exact","network":"solana-devnet","extra":{"feePayer":"TestFeePayer123"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := json.Marshal(tt.input)
			require.NoError(t, err)
			assert.JSONEq(t, tt.expected, string(result))
		})
	}
}
