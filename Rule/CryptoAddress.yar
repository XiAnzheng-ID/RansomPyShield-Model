rule BitcoinAddress
{
    meta:
        description = "Contains a valid Bitcoin address"
        author = "Didier Stevens (@DidierStevens)"
    strings:
		$btc = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,33}\b/
    condition:
        any of them
}
rule MoneroAddress
{
    meta:
        description = "Contains a valid Monero address"
        author = "Emilien LE JAMTEL (@__Emilien__)"
    strings:
		$monero = /\b4[0-9AB][0-9a-zA-Z]{93}|4[0-9AB][0-9a-zA-Z]{104}\b/
    condition:
        any of them
}