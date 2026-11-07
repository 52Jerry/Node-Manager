import pytest

from shared_manager.residential_import import ImportFormatError, parse_import


def test_supported_formats_and_password_delimiters():
    rows = parse_import("""# ignored
8.8.8.8:1080:alice:p:a,s:s
socks5://b%40b:p%3Aa%23s@1.1.1.1:1080#My%20Proxy
name,host,port,username,password
"Work, Home",9.9.9.9,1080,user,"secret,comma"
""")
    assert len(rows) == 3
    assert all(row.error is None for row in rows)
    assert rows[0].password == "p:a,s:s"
    assert rows[1].username == "b@b" and rows[1].password == "p:a#s"
    assert rows[1].name == "My Proxy"
    assert rows[2].name == "Work, Home" and rows[2].password == "secret,comma"
    assert all("password" not in row.summary() for row in rows)


def test_unauthenticated_proxy_and_bracketed_ipv6():
    rows = parse_import("8.8.8.8:1080\n[2606:4700:4700::1111]:1080:u:p")
    assert all(row.error is None for row in rows)
    assert rows[0].username == rows[0].password == ""
    assert rows[1].server == "2606:4700:4700::1111"


def test_malformed_rows_redact_all_source_fields():
    rows = parse_import("secret-password,private-secret,not-port,u,p\n8.8.8.8:99999:u:secret-password")
    assert all(row.error for row in rows)
    for row in rows:
        summary = row.summary()
        assert summary["name"].startswith("连接 ")
        assert summary["server"] == summary["username"] == ""
        assert "secret-password" not in str(summary)


def test_duplicate_and_private_destinations_rejected():
    rows = parse_import("8.8.8.8:1080:u:p\nsocks5://u:p@8.8.8.8:1080\n127.0.0.1:1080:u:p")
    assert rows[0].error is None
    assert rows[1].error and rows[2].error


def test_limits_and_empty_input():
    with pytest.raises(ImportFormatError):
        parse_import("\n# empty")
    with pytest.raises(ImportFormatError):
        parse_import("\n".join(f"8.8.8.8:{1000+i}:u:p" for i in range(51)))


def test_excel_bom_header_and_crlf():
    rows = parse_import("\ufeffname,host,port,username,password\r\n工作,8.8.8.8,1080,u,p\r\n")
    assert len(rows) == 1
    assert rows[0].line == 2 and rows[0].name == "工作" and rows[0].error is None


def test_standard_base64_socks_link():
    import base64
    encoded = base64.b64encode("user:p:a,s".encode()).decode()
    row = parse_import("socks://" + encoded + "@8.8.8.8:1080#Shared")[0]
    assert row.error is None and row.username == "user" and row.password == "p:a,s"


def test_csv_numeric_colon_password_is_not_mistaken_for_host_port():
    row = parse_import("Work,8.8.8.8,1080,user,secret:123")[0]
    assert row.error is None and row.password == "secret:123" and row.server == "8.8.8.8"
