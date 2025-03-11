import requests
import json

# Константы для API Vulners
API_KEY_VULNERS = 'WX6N52J3FWV6FSP5APSGI830U4Y0AI47NJ30SKS0L0T1D2T8TTCBM0GX4VLO4WE4'
VULNERS_API_URL = 'https://vulners.com/api/v3/search/lucene/'

# Список программного обеспечения для анализа
SOFTWARE_LIST = [
    {"program": "LibreOffice", "version": "6.0.7"},
    {"program": "7zip", "version": "18.05"},
    {"program": "Adobe Reader", "version": "2018.011.20035"},
    {"program": "nginx", "version": "1.14.0"},
    {"program": "Apache HTTP Server", "version": "2.4.29"},
    {"program": "DjVu Reader", "version": "2.0.0.27"},
    {"program": "Wireshark", "version": "2.6.1"},
    {"program": "Notepad++", "version": "7.5.6"},
    {"program": "Google Chrome", "version": "68.0.3440.106"},
    {"program": "Mozilla Firefox", "version": "61.0.1"}
]

def search_vulnerabilities(software_name: str, version: str) -> dict:
    """
    Выполняет запрос к API Vulners для поиска уязвимостей.
    
    :param software_name: Название программного обеспечения
    :param version: Версия программного обеспечения
    :return: JSON-ответ от API Vulners
    """
    query = f'"{software_name} {version}"'
    params = {
        'apiKey': API_KEY_VULNERS,
        'query': query,
        'size': 10  # Количество результатов
    }
    try:
        response = requests.get(VULNERS_API_URL, params=params)
        response.raise_for_status()  # Проверка на ошибки HTTP
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Ошибка при запросе к API Vulners: {e}")
        return {}

def analyze_software() -> list:
    """
    Анализирует список программного обеспечения на наличие уязвимостей.
    
    :return: Список словарей с результатами анализа
    """
    results = []

    for software in SOFTWARE_LIST:
        program = software['program']
        version = software['version']
        print(f"Анализ ПО: {program} {version}")

        # Поиск уязвимостей
        result = search_vulnerabilities(program, version)
        vulnerabilities = result.get('data', {}).get('search', [])

        software_result = {
            "program": program,
            "version": version,
            "vulnerabilities_found": False,
            "cve_list": [],
            "exploit_count": 0
        }

        if vulnerabilities:
            software_result["vulnerabilities_found"] = True
            cve_list = []
            exploit_count = 0

            for vuln in vulnerabilities:
                cve = vuln['_source'].get('cvelist', [])
                if cve:
                    cve_list.extend(cve)
                if vuln['_source'].get('exploit_available', False):
                    exploit_count += 1

            software_result["cve_list"] = cve_list
            software_result["exploit_count"] = exploit_count

            # Вывод списка CVE
            print(f"Список CVE: {', '.join(cve_list) if cve_list else 'Нет данных'}")

            # Информация об эксплойтах
            if exploit_count > 0:
                print(f"Найдено эксплойтов: {exploit_count}")
            else:
                print("Информация об эксплойтах: Нет данных")
        else:
            print(f"Уязвимости для {program} {version} не найдены.")

        results.append(software_result)
        print('-' * 40)

    return results

def save_results_to_json(results: list, filename: str):
    """
    Сохраняет результаты анализа в JSON-файл.
    
    :param results: Список словарей с результатами анализа
    :param filename: Имя файла для сохранения
    """
    try:
        with open(filename, 'w', encoding='utf-8') as file:
            json.dump(results, file, ensure_ascii=False, indent=4)
        print(f"Результаты успешно сохранены в файл: {filename}")
    except IOError as e:
        print(f"Ошибка при сохранении результатов в файл: {e}")

if __name__ == '__main__':
    # Анализируем ПО и получаем результаты
    analysis_results = analyze_software()

    # Сохраняем результаты в JSON-файл
    save_results_to_json(analysis_results, "vulnerability_analysis_results.json")