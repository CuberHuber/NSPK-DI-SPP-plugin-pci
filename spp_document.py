from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256


@dataclass
class SPP_document:
    """
    Объект документа в SPP
    """
    doc_id: int | None
    title: str
    abstract: str | None
    text: str | None
    web_link: str
    local_link: str | None
    other_data: dict | None
    pub_date: datetime
    load_date: datetime | None

    @property
    def hash(self):
        """
        Для проверки уникальности и новизны документа.

        :return:
        :rtype:
        """
        concat_name = self.title + '_' + self.web_link + '_' + str(self.pub_date.timestamp())
        return sha256(concat_name.encode('utf8')).digest()
