import forta_agent
from forta_agent import Finding, FindingType, FindingSeverity
from src.constants import COMPOUND_ADDRESS, BLACKLISTED_ADDRESSES


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    findings = []
    if transaction_event.to != COMPOUND_ADDRESS:
        return findings

    target_address = transaction_event.from_
    if target_address in BLACKLISTED_ADDRESSES:
        findings.append(Finding({
            'name': 'Blacklisted Address Alert',
            'description': f'Blacklisted address: {target_address} interacting with Compound Protocol',
            'alert_id': 'COMP_BL_ALERT',
            'type': FindingType.Suspicious,
            'severity': FindingSeverity.Critical,
            'metadata': {
                'address': target_address
            }
        }))

    return findings
