import logging
import asyncio
import requests
from aiogram import Bot, Dispatcher, types
from dotenv import dotenv_values
from aiogram.filters.command import Command
from utils.logic import scan_with_virustotal, scan_with_virustotal_file
from utils.keyboard import start_keyboard

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
config = dotenv_values(".env")
bot = Bot(token=config["BOT"])
dp = Dispatcher()

waiting_for_link = False


@dp.message(Command("start"))
async def start_button(message: types.Message):
    keyboard = start_keyboard()
    await message.answer("Выберите команду", reply_markup=keyboard)


@dp.message(lambda message: message.text == "Сократить ссылку")
async def request_link(message: types.Message):
    global waiting_for_link
    waiting_for_link = True
    await message.answer("Введите ссылку, которую хотите сократить:")


@dp.message(lambda message: waiting_for_link)
async def shorten_link(message: types.Message):
    global waiting_for_link
    url = message.text
    try:
        response = requests.get(f"http://clck.ru/--?url={url}")
        if response.status_code == 200:
            short_url = response.text
            await message.answer(f"Сокращенная ссылка: {short_url}")
        else:
            await message.answer(
                "Произошла ошибка при сокращении ссылки. Пожалуйста, проверьте правильность URL."
            )
    except Exception as e:
        await message.answer("Произошла ошибка. Пожалуйста, попробуйте еще раз.")
    finally:
        waiting_for_link = False


@dp.message(lambda message: message.text == "Просканировать ссылку")
async def request_scan_link(message: types.Message):
    await message.answer("Введите ссылку для сканирования:")


@dp.message(lambda message: message.text == "Сканировать файл")
async def request_scan_file(message: types.Message):
    await message.answer("Отправьте файл для сканирования:")


@dp.message()
async def handle_message(message: types.Message):
    if message.document:
        await scan_file(message)
    elif message.text:
        await scan_link(message)


async def scan_file(message: types.Message):
    await message.answer("Файл получен. Выполняется сканирование...")

    document = message.document
    file = await bot.download(document.file_id)

    file_bytes = file.read()
    result, message_text = await scan_with_virustotal_file(file_bytes)

    await message.answer(message_text)


async def scan_link(message: types.Message):
    url = message.text
    result, message_text = await scan_with_virustotal(url)
    await message.answer(message_text)


async def main():
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
