package masker

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMobile(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		wanted string
	}{
		{
			name:   "empty_should_not_masked",
			value:  "",
			wanted: "",
		},
		{
			name:   "less_prefix_len_should_work",
			value:  "1-23",
			wanted: "1-23*",
		},
		{
			name:   "equal_prefix_len_should_work",
			value:  "1-234",
			wanted: "1-234*",
		},
		{
			name:   "less_prefix_and_suffix_should_work",
			value:  "1-22260",
			wanted: "1-222*60",
		},
		{
			name:   "equals_prefix_and_suffix_should_work",
			value:  "1-222606",
			wanted: "1-222*606",
		},
		{
			name:   "greater_mask_len_should_work",
			value:  "1-2226060809",
			wanted: "1-222*809",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := Mobile(test.value)
			require.Equal(t, test.wanted, m)
		})
	}
}
