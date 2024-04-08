package masker

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEmail(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		wanted string
	}{
		{
			name:   "empty_email_should_not_masked",
			value:  "",
			wanted: "",
		},
		{
			name:   "invalid_email_should_not_masked",
			value:  "abc.com",
			wanted: "abc.com",
		},
		{
			name:   "less_mask_len_should_work",
			value:  "1@abc.com",
			wanted: "1*@abc.com",
		},
		{
			name:   "equal_mask_len_should_work",
			value:  "123@abc.com",
			wanted: "123*@abc.com",
		},
		{
			name:   "greater_mask_len_should_work",
			value:  "123456@abc.com",
			wanted: "123*@abc.com",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := Email(test.value)
			require.Equal(t, test.wanted, m)
		})
	}
}
