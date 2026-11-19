"""Tenant constants. Every security record belongs to exactly one organization."""
DEFAULT_ORG_ID = "00000000-0000-0000-0000-000000000001"   # migrated/legacy data lives here
UNSCOPED_ORG_ID = "00000000-0000-0000-0000-000000000000"  # platform-level audit rows (no tenant)


def doc_org(doc: dict) -> str:
    """Org of an event document; documents written before multi-tenancy belong to the default org."""
    org = (doc.get("org") or {}).get("id") if isinstance(doc.get("org"), dict) else None
    return str(org) if org else DEFAULT_ORG_ID
