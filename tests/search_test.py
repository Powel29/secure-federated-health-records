from search.service import derive_search_token, index_search_term


def test_same_term_same_key_gives_same_token():
    key = b"A" * 32

    token1 = derive_search_token(key, "diabetes")
    token2 = derive_search_token(key, "diabetes")

    assert token1 == token2


def test_different_terms_give_different_tokens():
    key = b"A" * 32

    token1 = derive_search_token(key, "diabetes")
    token2 = derive_search_token(key, "cancer")

    assert token1 != token2


def test_different_keys_give_different_tokens():
    key1 = b"A" * 32
    key2 = b"B" * 32

    token1 = derive_search_token(key1, "diabetes")
    token2 = derive_search_token(key2, "diabetes")

def test_index_search_term_stores_token(monkeypatch):
    stored = {}

    def fake_insert(conn, record_id, coded_term):
        stored["record_id"] = record_id
        stored["coded_term"] = coded_term

    monkeypatch.setattr(
    "search.service.insert_search_term",
    fake_insert,
)

    key = b"A" * 32

    token = index_search_term(
    None,
    "rec-123",
    key,
    "diabetes",
    insert_fn=fake_insert,
)

    assert stored["record_id"] == "rec-123"
    assert stored["coded_term"] == token
