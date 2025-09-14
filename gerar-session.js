const { TelegramClient } = require('telegram');
const { StringSession } = require('telegram/sessions');
const input = require('input');
require('dotenv').config();

const apiId = parseInt(process.env.API_ID);
const apiHash = process.env.API_HASH;

(async () => {
    const client = new TelegramClient(new StringSession(''), apiId, apiHash, {
        connectionRetries: 5,
    });

    await client.start({
        phoneNumber: async () => await input.text('📲 Digite seu número com DDI: '),
        password: async () => await input.text('🔐 Senha 2FA (se tiver): '),
        phoneCode: async () => await input.text('💬 Código do Telegram: '),
        onError: (err) => console.error('❌ Erro:', err),
    });

    console.log('\n✅ Login realizado com sucesso!');
    console.log('🔑 Cole a seguinte StringSession no seu .env:\n');
    console.log('TELEGRAM_SESSION="' + client.session.save() + '"');

    process.exit(0);
})(); 