# Guardião Mobile 🛡️

![Kotlin](https://img.shields.io/badge/Kotlin-B125EA?style=for-the-badge&logo=kotlin&logoColor=white)
![Android](https://img.shields.io/badge/Android-3DDC84?style=for-the-badge&logo=android&logoColor=white)
![Compose](https://img.shields.io/badge/Jetpack_Compose-4285F4?style=for-the-badge&logo=android&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

Um aplicativo Android multifuncional focado em **Segurança, Privacidade e Utilitários de Mídia**. O Guardião Mobile atua como um escudo local para o seu dispositivo, combinando um Firewall VPN interceptador de anúncios, um Antivírus de varredura profunda e um motor avançado de download e extração de mídia.

---

## 🚀 Funcionalidades

- **Antivírus e Auditoria do Sistema:** Inspeciona aplicativos instalados (diferenciando sistema vs. usuário), detecta aplicativos ocultos, analisa instaladores APKs baixados e sinaliza permissões críticas de espionagem.
- **Firewall VPN 24h & Anti-Malvertising:** Intercepta consultas DNS (IPv4 e IPv6) usando DoH (DNS over HTTPS). Bloqueia anúncios, rastreadores, malwares, conexões remotas suspeitas e permite alterar a sub-rede geográfica (mudança de país/IP).
- **Monitor de Memória RAM:** Identifica processos de terceiros consumindo recursos em segundo plano e oferece atalhos para encerrar ou restringir os processos.
- **Downloads Inteligentes de Mídia:** Baixe conteúdo nativo (Vídeo, Áudio ou Foto) do YouTube, Spotify, Instagram, TikTok, entre outros, apenas compartilhando o link com o aplicativo.
- **Organização Automática em Pastas:** Os arquivos são salvos diretamente em `Download/GuardiaoMobile/Videos`, `Fotos` ou `Audios`, sem necessidade de gerenciamento manual.
- **Extrator de Áudio Local:** Separe rapidamente a trilha de áudio (`.mp3`) de qualquer arquivo de vídeo (`.mp4`, `.mkv`, etc.) armazenado no aparelho usando o FFmpeg integrado.

---

## 🛠️ Tecnologias Utilizadas

- **Linguagem:** Kotlin
- **Interface:** Jetpack Compose (Material Design 3)
- **Rede & DNS:** OkHttp (DoH - DNS over HTTPS)
- **Processamento de Mídia:** FFmpeg (`com.yausername.ffmpeg`)
- **Extração Web:** yt-dlp-android (`io.github.junkfood02.youtubedl-android`)
- **Arquitetura:** MVVM (Model-View-ViewModel) com Coroutines e Flows
- **Compatibilidade:** Android 7.0+ (API 24+) a Android 15. Suporte a arquiteturas `arm64-v8a`, `armeabi-v7a`, `x86` e `x86_64`.

---

## 📦 Como Instalar

### Instalação via APK (Usuário Final)
1. Acesse a aba **[Releases](https://github.com/VictorEduardo-coder/GuardiaoMobile/releases)** deste repositório.
2. Baixe o arquivo `GuardiaoMobile.apk` mais recente.
3. No seu Android, abra o arquivo e conceda permissão para **Instalar aplicativos desconhecidos** (se solicitado).
4. *(Opcional)* Na Xiaomi/HyperOS ou Samsung One UI, permita que o aplicativo ignore as otimizações de bateria para que a VPN 24h não seja encerrada pelo sistema.

### Compilação Local (Desenvolvedores)
Clone o repositório e compile pelo terminal:
```bash
git clone [https://github.com/VictorEduardo-coder/GuardiaoMobile.git](https://github.com/VictorEduardo-coder/GuardiaoMobile.git)
cd GuardiaoMobile
./gradlew assembleDebug
```

O arquivo .apk gerado estará disponível em app/build/outputs/apk/debug/.

📖 Como Usar
Baixar Mídia: Abra qualquer rede social (YouTube, Spotify, etc.), toque em "Compartilhar", escolha o "Guardião Mobile" e selecione se deseja Vídeo, Áudio ou Foto. O download vai direto para a subpasta correta.

Verificar Vírus e Memória: Abra o aplicativo, vá até a aba Antivírus e toque em "Executar Varredura Antivírus Completa". Vá até a aba Memória para checar processos pesados em segundo plano.

Ativar VPN Firewall: Na aba VPN, selecione o país desejado (Brasil, EUA, Japão, etc.) e ative a chave. Aceite o prompt do Android para iniciar a proteção contra anúncios e malwares.

🔐 Privacidade e Segurança
Todo o processamento do Guardião Mobile (análise de vírus, cálculos de hash SHA-256, extração de mídia e filtragem de DNS) ocorre totalmente local no seu dispositivo. O aplicativo atua como um túnel isolado (10.1.10.1) e não transmite seus dados de navegação, senhas ou arquivos para servidores externos.

📄 Licença
Este projeto é desenvolvido e mantido por VictorEduardo-coder. Sinta-se à vontade para realizar forks e contribuir com melhorias!
