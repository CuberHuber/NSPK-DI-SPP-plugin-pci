"""
Парсер плагина SPP

1/2 документ плагина
"""
import logging
import os
import time
from datetime import datetime

from dateutil.parser import parse
from selenium.common import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as ec
from selenium.webdriver.support.ui import WebDriverWait, Select

from spp_document import SPP_document


class PCI:
    """
    Класс парсера плагина SPP

    :source: pci
    :link: https://www.pcisecuritystandards.org

    :warning Все необходимое для работы парсера должно находится внутри этого класса

    :_content_document: Это список объектов документа. При старте класса этот список должен обнулиться,
                        а затем по мере обработки источника - заполняться.


    """

    _content_document: list[SPP_document]

    # Типы документов на сайте
    _DOCUMENT_TYPES = (
        'All Document',
        'PCI DSS',
        'SAQ',
        'P2PE',
        'PTS',
        'Card Production',
        'MPoC',
        '3DS',
        'CPoC',
        'PIN',
        'SPoC',
        'TSP',
        'Software Security',
        'Programs and Certification',
        'Guidance Document',
        'Case Study',
    )
    HOST = 'https://www.pcisecuritystandards.org/document_library/'
    SOURCE_NAME = 'pci'

    CATEGORY_CLASS_NAME = 'doc_library_category parent_category'
    SUB_CATEGORY_CLASS_NAME = 'doc_library_category category'
    DOCUMENTS_ROW_CLASS_NAME = 'document_row_container'

    DOCUMENT_TYPE = ''

    def __init__(self, driver, document_type: str = 'All Document'):
        """
        Конструктор класса парсера

        По умолчанию внего ничего не передается, но если требуется (например: driver селениума), то нужно будет
        заполнить конфигурацию
        """
        assert document_type in self._DOCUMENT_TYPES
        self.DOCUMENT_TYPE = document_type
        self.driver = driver
        self.logger = logging.getLogger(self.__class__.__name__)

        # Обнуление списка
        self._content_document = []

        self.logger.debug(f"Parser class init completed")
        self.logger.info(f"Set source: {self.SOURCE_NAME}")
        ...

    def content(self) -> list[SPP_document]:
        """
        Главный метод парсера. Его будет вызывать платформа. Он вызывает метод _parse и возвращает список документов
        :return:
        :rtype:
        """
        self.logger.debug("Parse process start")
        self._parse()
        self.logger.debug("Parse process finished")
        return self._content_document

    def _parse(self):
        """
        Метод, занимающийся парсингом. Он добавляет в _content_document документы, которые получилось обработать
        :return:
        :rtype:
        """
        self.logger.debug(F"Parser enter to {self.HOST}")

        # ========================================
        # Тут должен находится блок кода, отвечающий за парсинг конкретного источника
        # -
        self.driver.set_page_load_timeout(40)
        self.driver.get(url=self.HOST)
        time.sleep(2)

        # прохождение панели с куками
        ccc_accept = self.driver.find_element(By.ID, 'ccc-notify-accept')
        if WebDriverWait(self.driver, 5).until(ec.element_to_be_clickable(ccc_accept)):
            ccc_accept.click()
            self.logger.debug(F"Parser enter notify accept")

        # Прокрутка до области с выбором типа документов
        WebDriverWait(self.driver, 5).until(ec.presence_of_element_located((By.ID, 'results')))
        if WebDriverWait(self.driver, 2).until(
                ec.element_to_be_clickable(self.driver.find_element(By.ID, 'search_by_doc_Type'))):
            document_category = self.driver.find_element(By.ID, 'document_category')

            # Выбор всех документов
            select = Select(document_category)
            select.select_by_value('all_documents')

            # обработка всех документов
            current_category = ''
            current_sub_category = ''
            rows_container = self.driver.find_element(By.ID, 'tabcontent').find_elements(By.TAG_NAME, 'div')

            # DRAFT test
            temp_max = 40
            temp_i = 0
            #

            for row in rows_container:
                # DRAFT test
                temp_i += 1
                if temp_i > temp_max:
                    break
                #

                # Если в списке есть категория, она записывается в текущую категорию.
                # И все следующие документы до новой категории, будут относить к этой категории
                if row.get_attribute('class') == self.CATEGORY_CLASS_NAME:
                    current_category = row.text
                # Аналогично категориям, только для субкатегорий
                elif row.get_attribute('class') == self.SUB_CATEGORY_CLASS_NAME:
                    current_sub_category = row.text
                #
                elif row.get_attribute('class') == self.DOCUMENTS_ROW_CLASS_NAME:

                    # Название документа
                    document_name = row.find_element(By.CLASS_NAME, 'document_name').text

                    # На сайте может быть элемент select для выбора версии документа или просто div с текстом версии
                    version_select_or_div = [el for el in row.find_elements(By.TAG_NAME, 'div') if
                                             'version_select' in el.get_attribute('id')]
                    document_version_and_pub_date = ''
                    if len(version_select_or_div) == 1:
                        try:
                            document_version_and_pub_date = Select(
                                version_select_or_div[0].find_element(By.TAG_NAME,
                                                                      'select')).first_selected_option.text
                        except:
                            document_version_and_pub_date = version_select_or_div[0].text

                    # Ссылка на документа
                    link_to_document = row.find_element(By.TAG_NAME, 'a').get_attribute('href')
                    document_version, document_pub_date = self._get_version_and_date(document_version_and_pub_date)

                    document = SPP_document(
                        doc_id=None,
                        title=document_name,
                        abstract=None,
                        text=None,
                        web_link=link_to_document,
                        local_link=None,
                        other_data={
                            'version': document_version,
                            'sub_category': current_sub_category,
                            'category': current_category,
                            'filename': link_to_document.split('/')[-1]
                        },
                        pub_date=document_pub_date,
                        load_date=None,
                    )

                    self._content_document.append(document)

                    self.logger.info(self._find_document_text_for_logger(document))

        time.sleep(5)
        self.driver.close()
        self.driver.quit()
        # ---
        # ========================================
        ...

    @staticmethod
    def _find_document_text_for_logger(doc: SPP_document):
        return f"Find document | name: {doc.title} | link to web: {doc.web_link} | publication date: {doc.pub_date}"

    @staticmethod
    def _get_version_and_date(ctx: str) -> tuple[str, datetime]:
        """
        Метод для конвертации даты времени и версии
        :param ctx:
        :type ctx:
        :return:
        :rtype:
        """
        version_and_date = ctx.split(' - ')
        if len(version_and_date) == 2:
            return version_and_date[0], datetime.fromtimestamp(parse(version_and_date[1], fuzzy=True).timestamp())
        if len(version_and_date) == 1 and version_and_date[0].startswith('v'):
            return version_and_date[0], datetime.min
        else:
            return '', datetime.fromtimestamp(parse(version_and_date[0], fuzzy=True).timestamp())

    @staticmethod
    def nasty_download(driver, path: str, url: str) -> str:
        """
        Метод для "противных" источников. Для разных источника он может отличаться.
        Но основной его задачей является:
            доведение driver селениума до файла непосредственно.

            Например: пройти куки, ввод форм и т. п.

        Метод скачивает документ по пути, указанному в driver, и возвращает имя файла, который был сохранен
        :param driver: WebInstallDriver, должен быть с настроенным местом скачивания
        :_type driver: WebInstallDriver
        :param url:
        :_type url:
        :return:
        :rtype:
        """

        with driver:
            driver.set_page_load_timeout(60)
            driver.get(url=url)
            time.sleep(3)

            # ========================================
            # Тут должен находится блок кода, отвечающий за конкретный источник
            # -

            # прохождение панели с куками
            try:
                ccc_accept = driver.find_element(By.ID, 'ccc-notify-accept')
                if ccc_accept:
                    if WebDriverWait(driver, 5).until(ec.element_to_be_clickable(ccc_accept)):
                        ccc_accept.click()
            except NoSuchElementException as e:
                ...
            except Exception as e:
                ...

            try:
                form = driver.find_element(By.ID, 'agreement_form')
                if form:
                    WebDriverWait(driver, 5).until(ec.presence_of_element_located((By.ID, 'agreement_form')))
                    driver.find_element(By.ID, 'contact_name').send_keys('Company')
                    driver.find_element(By.ID, 'contact_title').send_keys('People')
                    driver.find_element(By.ID, 'company').send_keys('cbr')
                    driver.find_element(By.ID, 'country').send_keys('Russian')

                    WebDriverWait(driver, 5).until(ec.presence_of_element_located(
                        (By.XPATH, '//*[@id="doc_agreement"]/div[4]/input[1]')))

                    if WebDriverWait(driver, 5).until(
                            ec.element_to_be_clickable(
                                driver.find_element(By.XPATH, '//*[@id="doc_agreement"]/div[4]/input[1]'))):
                        driver.find_element(By.XPATH, '//*[@id="doc_agreement"]/div[4]/input[1]').click()
            except NoSuchElementException as e:
                ...
            except Exception as e:
                ...

            # ---
            # ========================================

            # Ожидание полной загрузки файла
            while not os.path.exists(path + '/' + url.split('/')[-1]):
                time.sleep(1)

            if os.path.isfile(path + '/' + url.split('/')[-1]):
                # filename
                return url.split('/')[-1]
            else:
                return ""
