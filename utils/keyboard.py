from aiogram import types


def start_keyboard():
    kb = [
        [
            types.KeyboardButton(text="Сократить ссылку"),
            types.KeyboardButton(text="Просканировать ссылку"),
            types.KeyboardButton(text="Сканировать файл"),
        ]
    ]
    return types.ReplyKeyboardMarkup(keyboard=kb, resize_keyboard=True)
