package k6ecdsa

import (
	"testing"
)

func TestSignAndVerifyECDSA(t *testing.T) {
	ssn := "123456789"
	// Example PEM formatted private and public keys
	privateKey := `-----BEGIN PRIVATE KEY----- 
	MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgolUrWk44a8sWFQzxEmgI9NSJjn4RYTqzl2POanISe6KhRANCAAQqwpz+CRWY8ps+9DN3aHdmhV6J7fJZSLiO6lhn5sBFbdVp9qCfhvfl/lUCohHxGxp7cNOg2Qq0wVGRQ7K6TS+O 
	-----END PRIVATE KEY-----`

	payload := `{"Type":"INDIVIDUAL","DOB":"20200710","_nationality":"UK","Title":"Mr","FirstName":"Danial","LastName":"John","_key":"123455qqqwqw","_Gender":"MALE","Identification":[{"Type":"SSN","Value":"` + ssn + `"}],"Contact":{"PhoneNumber":"99007689","Email":"daniel.john` + ssn + `@netxd.com"},"Address":{"AddressLine1":"2261 Market Street #4000","City":"DALLAS","State":"TN","Country":"US","Zip":"34355"},"UserName":"daniel.john` + ssn + `@netxd.com","Password":"Test@1234","_Program":"ATOMIC","_ParentCustomerId":"100000000587309","KycStatus":"ACTIVE","_KycData":{"applicationId":"KYC202104139250582925465569","refId":"FF35042","fee":1.5,"kycStatus":{"ofacStatus":"SERVICE_GOOD","bureauStatus":"SERVICE_GOOD","ipStatus":"SERVICE_GOOD","mobileStatus":"SERVICE_GOOD","kycStatus":"SERVICE_GOOD","emailStatus":"SERVICE_GOOD","idvStatus":"SERVICE_UNSUBSCRIBE","sentilinkStatus":"SERVICE_UNSUBSCRIBE"}},"_CustomerData":"INDIVIDUAL ACCOUNT"}`

	crypto := &Crypto{}

	// Sign the payload
	signature, err := crypto.SignECDSAWithPEM(privateKey, []byte(payload))
	if err != nil {
		t.Fatalf("Failed to sign payload: %v", err)
	}

	// Verify the signature
	valid, err := crypto.verifyECDSASignatureWithPEM(privateKey, string(payload), signature)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	if !valid {
		t.Fatalf("Signature is not valid")
	}
}
