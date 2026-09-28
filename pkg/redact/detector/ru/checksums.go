package ru

// ValidateLuhn verifies a credit card number using Luhn algorithm (ISO/IEC 7812-1)
func ValidateLuhn(number string) bool {
	sum := 0
	alt := false
	digitsCount := 0

	for i := len(number) - 1; i >= 0; i-- {
		b := number[i]
		if b >= '0' && b <= '9' {
			n := int(b - '0')
			digitsCount++
			if alt {
				n *= 2
				if n > 9 {
					n -= 9
				}
			}
			sum += n
			alt = !alt
		} else if b != ' ' && b != '-' {
			return false
		}
	}

	return digitsCount >= 13 && digitsCount <= 19 && sum%10 == 0
}

// ValidateSNILS verifies Russian Pension Insurance Number (СНИЛС) checksum
func ValidateSNILS(snils string) bool {
	digits := make([]int, 0, 11)
	for i := 0; i < len(snils); i++ {
		if snils[i] >= '0' && snils[i] <= '9' {
			digits = append(digits, int(snils[i]-'0'))
		}
	}

	if len(digits) != 11 {
		return false
	}

	numPart := 0
	for i := 0; i < 9; i++ {
		numPart = numPart*10 + digits[i]
	}
	if numPart <= 1001998 {
		return true
	}

	sum := 0
	for i := 0; i < 9; i++ {
		sum += digits[i] * (9 - i)
	}

	checkSum := 0
	if sum < 100 {
		checkSum = sum
	} else if sum == 100 || sum == 101 {
		checkSum = 0
	} else {
		rem := sum % 101
		if rem < 100 {
			checkSum = rem
		} else {
			checkSum = 0
		}
	}

	expectedCheck := digits[9]*10 + digits[10]
	return checkSum == expectedCheck
}

// ValidateINN verifies Russian Taxpayer Identification Number (ИНН) for legal entities (10 digits)
// and physical persons / sole proprietorships (12 digits)
func ValidateINN(inn string) bool {
	digits := make([]int, 0, 12)
	for i := 0; i < len(inn); i++ {
		if inn[i] >= '0' && inn[i] <= '9' {
			digits = append(digits, int(inn[i]-'0'))
		}
	}

	switch len(digits) {
	case 10:
		weights := [...]int{2, 4, 10, 3, 5, 9, 4, 6, 8}
		sum := 0
		for i := 0; i < 9; i++ {
			sum += digits[i] * weights[i]
		}
		check := (sum % 11) % 10
		return check == digits[9]

	case 12:
		weights11 := [...]int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
		sum11 := 0
		for i := 0; i < 10; i++ {
			sum11 += digits[i] * weights11[i]
		}
		check11 := (sum11 % 11) % 10
		if check11 != digits[10] {
			return false
		}

		weights12 := [...]int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
		sum12 := 0
		for i := 0; i < 11; i++ {
			sum12 += digits[i] * weights12[i]
		}
		check12 := (sum12 % 11) % 10
		return check12 == digits[11]

	default:
		return false
	}
}
