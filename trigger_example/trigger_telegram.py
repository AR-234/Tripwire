import logging, requests

# For a new Telegram bot
# Write BotFather
# go with /new and fill out all parameter
# you get a HTTP API Token this goes into telegram_botToken
# write your got
# replace {token} with your token: https://api.telegram.org/bot{token}/getUpdates
# get the chatID and insert it into chatId

#Config Start
telegram_botToken = "[TOKEN]"
telegram_chatId   = "[Chat-ID]"
#Config End

def telegram_message(message):
    global telegram_botToken, telegram_chatId
    sendText = "https://api.telegram.org/bot" + telegram_botToken + "/sendMessage?chat_id=" + telegram_chatId + "&parse_mode=Markdown&text=" + message
    response = requests.get(sendText)
    if response.status_code != 200:
        logging.warning("Could not send message over the telegram API.")
    return response.json()

def icmp_trigger(eth, iph, icmph):
    logging.info("Sending Telegram message..")
    telegram_message("ICMP-Wire was tripped by "+ iph.src_addr + " (" + eth.src_mac + ")")

def tcp_trigger(eth, iph, tcph):
    logging.info("Sending Telegram message..")
    telegram_message("Port-Wire was tripped by "+ iph.src_addr + " (" + eth.src_mac + ") on Port " + str(tcph.dest_port))
