package masker

const (
	MobilePrefixLen = 5
	MobileSuffixLen = 3
)

// Mobile mask mobile number: [CountryCode]-[MobileNumber]
func Mobile(v string) string {
	l := len([]rune(v))
	if l == 0 {
		return ""
	}

	return addOverlay(v, MobilePrefixLen, MobileSuffixLen, "*")
}
