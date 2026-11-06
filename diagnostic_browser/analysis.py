"""Deterministic evidence fingerprinting and baseline comparisons; NO AI inference."""
from __future__ import annotations
import hashlib
import json
import re
from collections import Counter
from typing import Iterable

SIGNATURE_FIELDS = ('route','method','status','resource','error_class','error_code','socket_state','detail_code','target','code')
ISSUE_STATES = frozenset({'OPEN','ACKNOWLEDGED','RESOLVED','IGNORED'})

def fingerprint(event: dict) -> str:
    # All event fields have already passed the strict typed sanitizer.
    d=event['fields']
    sig={'kind':event['kind'], 'fields':{k:d[k] for k in SIGNATURE_FIELDS if k in d}}
    return hashlib.sha256(json.dumps(sig,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def count_signatures(events: Iterable[dict], failures_only=True) -> dict[str,int]:
    counts:Counter=Counter()
    for event in events:
        if failures_only and event['severity'] not in {'error','critical','warning'}:continue
        counts[fingerprint(event)]+=1
    return dict(sorted(counts.items()))

def compare(baseline: dict[str,int], current: dict[str,int]) -> list[dict]:
    result=[]
    for key in sorted(set(baseline)|set(current)):
        old=baseline.get(key,0);new=current.get(key,0)
        label='NEW' if new and not old else 'PERSISTENT' if new and old else 'NOT_OBSERVED'
        result.append({'fingerprint':key,'previous_count':old,'current_count':new,'classification':label})
    return result

def validate_ticket(ticket:str) -> str:
    # Vendor ticket number is a controlled alphanumeric reference, not free text.
    if not isinstance(ticket,str) or not re.fullmatch('[A-Za-z0-9-]{1,40}',ticket):
        raise ValueError('ticket must be a short alphanumeric reference')
    return ticket
