
from typing import List, Union
from pydantic import BaseModel, ValidationError


class Token(BaseModel):
    access_token: str
    token_type: str

class TokenDecoded(Token):
    scopes: List[str]
    username: str

class TokenData(BaseModel):
    username: Union[str, None] = None
    #scopes in JWT
    scopes: List[str] = []