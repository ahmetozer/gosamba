package parent

// creditWindow is the maximum number of credits the server will grant to a
// single client connection. 512 matches what Windows Server 2019 advertises
// and is well within MS-SMB2 §3.3.1.2's server credit limit.
const creditWindow = 512

// grantCredits computes how many credits to award in a response header.
//
// Policy: grant max(creditCharge, min(creditWindow, requested)) so that:
//   - the client always gets back at least as many credits as the operation
//     consumed (CreditCharge), keeping the balance non-negative;
//   - when the client asks for more (CreditRequest > CreditCharge), we satisfy
//     up to creditWindow, letting the pipeline grow quickly;
//   - we never exceed creditWindow, bounding server-side per-connection state.
//
// reqCredit is the value from the request header's Credits field (bytes 14-15),
// which on inbound requests carries the client's credit request (the number of
// new credits the client wants to be granted). creditCharge is the CreditCharge
// from the same request header (how many credits the operation consumed).
func grantCredits(creditCharge, reqCredit uint16) uint16 {
	// Minimum: at least replace what was consumed (and never zero).
	floor := creditCharge
	if floor < 1 {
		floor = 1
	}
	// Clamp client's request to the window, but the charge floor always wins:
	// if creditCharge exceeds creditWindow we must still grant the charge so
	// the client's credit balance never goes negative (MS-SMB2 §3.3.5.2).
	g := reqCredit
	if g < floor {
		g = floor
	}
	if g > creditWindow {
		g = creditWindow
	}
	if g < floor {
		g = floor
	}
	return g
}
