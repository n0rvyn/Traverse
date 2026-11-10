package issuance

import "testing"

func TestTermsReferenceIsNotAnAPIEndpoint(t *testing.T) {
	for _, value := range []string{"", "https://ca.example.test/terms#current", "data:text/plain,Do%20what%20thou%20wilt", "data:,Plain%20terms", "data:text/plain,A%20question?yes", "data:text/plain;base64,VGVybXM=", "data:text/plain;charset=utf-8,%E8%AF%B4%E6%98%8E"} {
		if err := validateTermsURI(value); err != nil {
			t.Fatal("Safe terms rejected", err)
		}
	}
	for _, value := range []string{"http://ca.example.test/terms", "https://secret@ca.example.test/terms", "javascript:alert(1)", "file:///private/key", "data:text/html,<script>ignored</script>", "data:text/plain;charset=utf-8;charset=us-ascii,duplicate", "data:text/plain;base64,broken!", "data:text/plain,%FF", "data:text/plain,valid?%FF", "data:text/plain,%C3%A9"} {
		if err := validateTermsURI(value); err == nil {
			t.Fatal("Unsafe or invalid terms reference accepted")
		}
	}
}
