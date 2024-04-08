package masker

func addOverlay(v string, prefixLen, suffixLen int, mask string) string {

	n := len(v)
	if n > prefixLen {

		if suffixLen <= 0 {
			return v[:prefixLen] + mask
		}

		left := n - prefixLen
		if left > suffixLen {
			return v[:prefixLen] + mask + v[n-suffixLen:]
		}

		return v[:prefixLen] + mask + v[prefixLen:]
	}

	return v + mask
}
