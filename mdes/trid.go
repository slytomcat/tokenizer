package mdes

import (
	"encoding/json"

	"github.com/slytomcat/tokenizer/tools"
)

// NewTRID is the implementation of async request for new TRID
func (m MDESapi) NewTRID(id, name string) error {

	tokenRequestor := TokenRequestor{
		EntityID:                                   id,
		PaymentAppID:                               "M4MCLOUDDSRP", // const
		ConsumerFacingEntityName:                   name,
		DebitCreditIndicator:                       "BOTH",
		ProvidePaymentAccountReference:             true,
		EnableTransactionIssuerResponseInformation: true,
		WrappedEncryptionHashAlgorithm:             "SHA512",
	}

	payload, _ := json.Marshal(struct {
		ResponseHost    string           `json:"responseHost"`
		RequestID       string           `json:"requestId"`
		TokenRequestors []TokenRequestor `json:"tokenRequestors"`
	}{
		ResponseHost:    "assist.ru",
		RequestID:       tools.UniqueID(),
		TokenRequestors: []TokenRequestor{tokenRequestor},
	})

	_, err := m.request("POST", m.urlNewTRID, payload)

	return err
}
