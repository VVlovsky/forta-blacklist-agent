from forta_agent import FindingSeverity, FindingType, create_transaction_event
from agent import handle_transaction
from constants import COMPOUND_ADDRESS, BLACKLISTED_ADDRESSES


class TestBlacklistAgent:
    def test_returns_empty_findings_if_address_is_not_blacklisted(self):
        tx_event = create_transaction_event({
            'transaction': {
                'from': "0xNOTBLACKLISTEDGUYJUSTTRUSTME",
                'to': COMPOUND_ADDRESS,
            }})

        findings = handle_transaction(tx_event)
        assert len(findings) == 0

    def test_returns_finding_if_address_is_blacklisted(self):
        tx_event = create_transaction_event({
            'transaction': {
                'from': BLACKLISTED_ADDRESSES[0],
                'to': COMPOUND_ADDRESS,
            }})

        findings = handle_transaction(tx_event)
        for finding in findings:
            assert finding.name == 'Blacklisted Address Alert'
            assert finding.alert_id == 'COMP_BL_ALERT'
            assert finding.description == f'Blacklisted address: {BLACKLISTED_ADDRESSES[0]} interacting with Compound Protocol'
            assert finding.severity == FindingSeverity.Critical
            assert finding.type == FindingType.Suspicious
