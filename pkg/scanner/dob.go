package scanner

// A date of birth is a date, and a date is what a log is full of, so nothing
// about its shape tells `DOB=1986-12-01` from `created_at=1986-12-01`. The
// FastAPI service in leak-radar repo-risks 2026-10-19 (HealthRex/CDSS) printed
// `Patient data: gender=0, DOB=1986-12-01` at INFO on every lookup, and the
// date passed in 30 of 30 runs: it is digits and punctuation, far below any
// threshold, and no key on the default list names it.
//
// So the date is known by its key, the way a phone or an identity number is:
// a calendar date in ISO order (1986-12-01, 1986/12/01, with an optional
// time), day-month-year or month-day-year with '/', '.' or '-' (01/12/1986,
// 1.12.1986, 12-01-1986), as the value of a key whose words say "date of
// birth" (dob, DOB, birth_date, birthDate, date_of_birth, dateOfBirth,
// birthday, patient_dob). A date under any other key (created_at, expires,
// start_date) and a date in prose stay.

// dobKeyWords are the last word of a key that holds a date of birth on its
// own, as splitKeyWords lowercases it (dob, patient_dob, birthDate run
// together as birthdate).
var dobKeyWords = map[string]bool{
	"dob": true, "birthdate": true, "birthday": true, "dateofbirth": true, "born": true,
}

// isDOBKey reports whether key names a date of birth.
func isDOBKey(key string) bool {
	var words [maxKeyWords]string
	n := splitKeyWords(key, &words)
	return n > 0 && isDOBKeyWords(words[:n])
}

// isDOBKeyWords judges a key by its last word (dob, birthday), by "birth
// date" (birth_date, birthDate) or by "date of birth" (date_of_birth,
// dateOfBirth). A key that only starts with such a word (dob_verified,
// birth_date_format) is not one.
func isDOBKeyWords(parts []string) bool {
	np := len(parts)
	last := parts[np-1]
	switch last {
	case "date":
		return np >= 2 && parts[np-2] == "birth"
	case "birth":
		return np >= 3 && parts[np-2] == "of" && parts[np-3] == "date"
	}
	return dobKeyWords[last]
}

// matchKeyedDate matches a calendar date at line[i:]: four-digit year first
// (1986-12-01, 1986/12/01, 1986.12.01), optionally followed by a time
// (T00:00:00, T00:00:00.000Z, T00:00:00+02:00, or a space and HH:MM:SS); or
// a one- or two-digit day and month before a four-digit year, all three
// joined by the same '/', '.' or '-' (01/12/1986, 1.12.1986, 12-01-1986),
// where either order of day and month is accepted. The year is 1900-2099,
// the month 1-12 and the day 1-31. The caller has checked that the run is
// the value of a date-of-birth key. It returns the end index or 0.
func matchKeyedDate(line string, i int) int {
	n := len(line)
	if i+4 <= n && digitGroup(line, i, 4) {
		return matchISODate(line, i)
	}
	// day and month first: d{1,2} sep d{1,2} sep d{4}
	j := i
	a, j := readDigits(line, j, 2)
	if a < 0 || j >= n {
		return 0
	}
	sep := line[j]
	if sep != '/' && sep != '.' && sep != '-' {
		return 0
	}
	b, j := readDigits(line, j+1, 2)
	if b < 0 || j >= n || line[j] != sep {
		return 0
	}
	if !digitGroup(line, j+1, 4) {
		return 0
	}
	year := atoiN(line, j+1, 4)
	j += 5
	if !plausibleYear(year) || !plausibleDayMonth(a, b) {
		return 0
	}
	return j
}

// matchISODate matches YYYY sep MM sep DD at line[i:], where line[i:i+4] is
// known to be digits, with an optional time part, and returns the end or 0.
func matchISODate(line string, i int) int {
	n := len(line)
	year := atoiN(line, i, 4)
	j := i + 4
	if j >= n {
		return 0
	}
	sep := line[j]
	if sep != '-' && sep != '/' && sep != '.' {
		return 0
	}
	if !digitGroup(line, j+1, 2) || j+3 >= n || line[j+3] != sep || !digitGroup(line, j+4, 2) {
		return 0
	}
	month := atoiN(line, j+1, 2)
	day := atoiN(line, j+4, 2)
	j += 6
	if !plausibleYear(year) || month < 1 || month > 12 || day < 1 || day > 31 {
		return 0
	}
	return skipTimeOfDay(line, j)
}

// skipTimeOfDay extends a date at line[:j] over a time written right after
// it: 'T' or one space, HH:MM, optional :SS, optional fraction, optional
// Z or ±HH:MM / ±HHMM zone. Without a well-formed time it returns j.
func skipTimeOfDay(line string, j int) int {
	n := len(line)
	k := j
	if k < n && (line[k] == 'T' || line[k] == 't' || line[k] == ' ') {
		k++
	} else {
		return j
	}
	if !digitGroup(line, k, 2) || k+2 >= n || line[k+2] != ':' || !digitGroup(line, k+3, 2) {
		return j
	}
	k += 5
	if k+2 < n && line[k] == ':' && digitGroup(line, k+1, 2) {
		k += 3
		if k+1 < n && (line[k] == '.' || line[k] == ',') && isASCIIDigit(line[k+1]) {
			k++
			for k < n && isASCIIDigit(line[k]) {
				k++
			}
		}
	}
	switch {
	case k < n && (line[k] == 'Z' || line[k] == 'z'):
		k++
	case k < n && (line[k] == '+' || line[k] == '-') && digitGroup(line, k+1, 2):
		k += 3
		if k+2 < n && line[k] == ':' && digitGroup(line, k+1, 2) {
			k += 3
		} else if digitGroup(line, k, 2) {
			k += 2
		}
	}
	return k
}

// readDigits reads one to max digits at line[i:] and returns their value and
// the index after them, or -1 when there is no digit at line[i].
func readDigits(line string, i, max int) (int, int) {
	v := 0
	j := i
	for j < len(line) && j-i < max && isASCIIDigit(line[j]) {
		v = v*10 + int(line[j]-'0')
		j++
	}
	if j == i {
		return -1, i
	}
	return v, j
}

// atoiN returns the value of the k digits at line[i:], which the caller has
// checked are digits.
func atoiN(line string, i, k int) int {
	v := 0
	for m := 0; m < k; m++ {
		v = v*10 + int(line[i+m]-'0')
	}
	return v
}

func plausibleYear(y int) bool { return y >= 1900 && y <= 2099 }

// plausibleDayMonth accepts a and b as a day and a month in either order.
func plausibleDayMonth(a, b int) bool {
	return a >= 1 && b >= 1 && ((a <= 31 && b <= 12) || (a <= 12 && b <= 31))
}

// isDOBValue reports whether val, a whole URL parameter value, is a calendar
// date as matchKeyedDate reads it. The caller checks the key.
func isDOBValue(val string) bool {
	if val == "" || !isASCIIDigit(val[0]) {
		return false
	}
	return matchKeyedDate(val, 0) == len(val)
}
