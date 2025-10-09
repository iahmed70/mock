from unittest import mock

import pytest

from presidio_anonymizer.operators import Encrypt, AESCipher
from presidio_anonymizer.entities import InvalidParamError


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_then_aes_encrypt_called_and_its_result_is_returned(
    mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text", params={"key": "key"})

    assert anonymized_text == expected_anonymized_text


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_with_bytes_key_then_aes_encrypt_result_is_returned(
        mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text",
                                        params={"key": b'1111111111111111'})

    assert anonymized_text == expected_anonymized_text


def test_given_verifying_an_valid_length_key_no_exceptions_raised():
    Encrypt().validate(params={"key": "128bitslengthkey"})


def test_given_verifying_an_valid_length_bytes_key_no_exceptions_raised():
    Encrypt().validate(params={"key": b'1111111111111111'})


def test_given_verifying_an_invalid_length_key_then_ipe_raised():
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": "key"})

@mock.patch.object(AESCipher, "encrypt") # hint: replace encrypt with the method that you want to mock
def test_given_verifying_an_invalid_length_bytes_key_then_ipe_raised(mock_encrypt): # hint: replace mock_encrypt with a proper name for your mocker
    # Here: add setup for mocking
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": b'1111111111111111'})


@mock.patch.object(AESCipher, "encrypt")  # hint: replace encrypt with the method that you want to mock
def test_given_verifying_an_invalid_length_bytes_key_then_ipe_raised(mock_encrypt):
    invalid_key = b'111111111111111'  # 15 bytes → invalid (not 128/192/256 bits)
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": invalid_key})


def test_operator_name():
    operator = Encrypt()
    # Handle both attribute and callable implementations
    name = operator.operator_name if not callable(operator.operator_name) else operator.operator_name()
    assert name.lower() == "encrypt"

@mock.patch.object(AESCipher, "is_valid_key_size")
def test_given_verifying_an_invalid_length_bytes_key_then_ipe_raised(mock_is_valid_key_size):
    # Force AESCipher.is_valid_key_size to return False to trigger the InvalidParamError path
    mock_is_valid_key_size.return_value = False

    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": b'1111111111111111'})

def test_operator_type():
    operator = Encrypt()
    assert operator.operator_type().name == "Anonymize"
    
@pytest.mark.parametrize("key", [
    "A" * 16,
    "B" * 24,
    "C" * 32,
    b"A" * 16,
    b"B" * 24,
    b"C" * 32,
])
def test_valid_keys(key):
    """Validate should pass for all valid AES key sizes (128, 192, 256 bits)."""
    Encrypt().validate(params={"key": key})