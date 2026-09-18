package scanner

// Issuer identification number (IIN) ranges and the card-number lengths each
// network issues, as assigned under ISO/IEC 7812 and published by the networks
// (Visa, Mastercard, American Express, Discover, JCB, Diners Club, UnionPay;
// the consolidated "Payment card number" table mirrors the same assignments).
//
// A Luhn checksum alone accepts one random digit string in ten, so every
// 13–19 digit timestamp, order number or case number has a 10% chance of being
// called a card. On 300k lines of a real access log every single "card" the
// checksum found — 374 of them — was a 13-digit millisecond timestamp. Requiring
// a real issuer prefix and a length that issuer actually uses closes that.
//
// Kept as data so a new range is a row, not a branch. Maestro (50, 56–69,
// 12–19 digits) is deliberately left out: its range is so wide it would admit
// most of the numeric IDs this check exists to reject, and the scheme was
// retired in Europe in 2023.
type binRange struct {
	lo, hi  uint32 // inclusive prefix range; both are `digits` digits long
	digits  int    // how many leading digits the range spans
	lengths uint32 // bitmask of accepted total lengths (bit n set = length n)
}

func lens(ns ...int) uint32 {
	var m uint32
	for _, n := range ns {
		m |= 1 << uint(n)
	}
	return m
}

var cardBINs = []binRange{
	// Visa
	{lo: 4, hi: 4, digits: 1, lengths: lens(13, 16, 19)},
	// Mastercard
	{lo: 51, hi: 55, digits: 2, lengths: lens(16)},
	{lo: 2221, hi: 2720, digits: 4, lengths: lens(16)},
	// American Express
	{lo: 34, hi: 34, digits: 2, lengths: lens(15)},
	{lo: 37, hi: 37, digits: 2, lengths: lens(15)},
	// Discover
	{lo: 6011, hi: 6011, digits: 4, lengths: lens(16, 19)},
	{lo: 622126, hi: 622925, digits: 6, lengths: lens(16, 19)},
	{lo: 644, hi: 649, digits: 3, lengths: lens(16, 19)},
	{lo: 65, hi: 65, digits: 2, lengths: lens(16, 19)},
	// JCB
	{lo: 3528, hi: 3589, digits: 4, lengths: lens(16, 17, 18, 19)},
	// Diners Club
	{lo: 300, hi: 305, digits: 3, lengths: lens(14, 15, 16, 17, 18, 19)},
	{lo: 36, hi: 36, digits: 2, lengths: lens(14, 15, 16, 17, 18, 19)},
	{lo: 38, hi: 39, digits: 2, lengths: lens(14, 15, 16, 17, 18, 19)},
	// UnionPay
	{lo: 62, hi: 62, digits: 2, lengths: lens(16, 17, 18, 19)},
}

// matchesCardBIN reports whether the digit run at indices into line starts with
// a known issuer prefix and has a length that issuer uses. It reads at most six
// leading digits straight from the line, so it allocates nothing.
func matchesCardBIN(line string, indices []int) bool {
	n := len(indices)
	for i := range cardBINs {
		r := &cardBINs[i]
		if r.lengths&(1<<uint(n)) == 0 || r.digits > n {
			continue
		}
		var p uint32
		for _, idx := range indices[:r.digits] {
			p = p*10 + uint32(line[idx]-'0')
		}
		if p >= r.lo && p <= r.hi {
			return true
		}
	}
	return false
}
