import requests
import asyncio
import logging
from dotenv import dotenv_values

logger = logging.getLogger(__name__)
config = dotenv_values(".env")


async def scan_with_virustotal(url):
    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": config["VIRUS_TOTAL"],
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = f"url={requests.utils.quote(url)}"

    try:
        response = requests.post(api_url, headers=headers, data=data)
        logger.info(f"VirusTotal POST request status: {response.status_code}")

        if response.status_code == 200:
            analysis_id = response.json()["data"]["id"]
            await asyncio.sleep(10)

            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            analysis_response = requests.get(analysis_url, headers=headers)
            logger.info(
                f"VirusTotal GET request status: {analysis_response.status_code}"
            )

            if analysis_response.status_code == 200:
                report = analysis_response.json()
                stats = report["data"]["attributes"]["stats"]
                malicious_count = stats["malicious"]

                if malicious_count > 0:
                    return report, "Ссылка небезопасна."
                else:
                    return report, "Ссылка безопасна."
            else:
                logger.error(
                    f"Error fetching analysis results: {analysis_response.text}"
                )
                return None, "Ошибка при получении результата анализа VirusTotal."
        else:
            logger.error(f"Error submitting URL for analysis: {response.text}")
            return None, f"Ошибка при отправке ссылки на анализ: {response.text}"

    except Exception as e:
        logger.exception("Exception during VirusTotal scan:")
        return None, f"Произошла ошибка: {str(e)}"


async def scan_with_virustotal_file(file_bytes):
    api_url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": config["VIRUS_TOTAL"]}

    files = {"file": ("file", file_bytes)}

    try:
        response = requests.post(api_url, headers=headers, files=files)
        logger.info(f"VirusTotal POST request status: {response.status_code}")

        if response.status_code == 200:
            analysis_id = response.json()["data"]["id"]
            await asyncio.sleep(10)

            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            analysis_response = requests.get(analysis_url, headers=headers)
            logger.info(
                f"VirusTotal GET request status: {analysis_response.status_code}"
            )

            if analysis_response.status_code == 200:
                report = analysis_response.json()
                stats = report["data"]["attributes"]["stats"]
                malicious_count = stats["malicious"]

                if malicious_count > 0:
                    return report, "Файл небезопасен."
                else:
                    return report, "Файл безопасен."
            else:
                logger.error(
                    f"Error fetching analysis results: {analysis_response.text}"
                )
                return None, "Ошибка при получении результата анализа VirusTotal."
        else:
            logger.error(f"Error submitting file for analysis: {response.text}")
            return None, f"Ошибка при отправке файла на анализ: {response.text}"

    except Exception as e:
        logger.exception("Exception during VirusTotal file scan:")
        return None, f"Произошла ошибка: {str(e)}"
