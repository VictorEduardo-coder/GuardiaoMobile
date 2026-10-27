# Guardião Mobile 🛡️

Um aplicativo Android multifuncional focado em **Segurança, Privacidade e Utilitários de Mídia**. O Guardião Mobile atua como um escudo local para o seu dispositivo, combinando um Firewall VPN interceptador de anúncios, um Antivírus de varredura profunda e um motor avançado de download e extração de mídia.

## 🚀 Funcionalidades

* **Antivírus e Auditoria do Sistema:** Inspeciona aplicativos instalados (diferenciando sistema vs. usuário), detecta aplicativos ocultos, analisa instaladores APKs baixados e sinaliza permissões críticas de espionagem.
* **Firewall VPN 24h & Anti-Malvertising:** Intercepta consultas DNS (IPv4 e IPv6) usando DoH (DNS over HTTPS). Bloqueia anúncios, rastreadores, malwares, conexões remotas suspeitas e permite alterar a sub-rede geográfica (mudança de país/IP).
* **Monitor de Memória RAM:** Identifica processos de terceiros consumindo recursos em segundo plano e oferece atalhos para encerrar ou restringir os processos.
* **Downloads Inteligentes de Mídia:** Baixe conteúdo nativo (Vídeo, Áudio ou Foto) do YouTube, Spotify, Instagram, TikTok, entre outros, apenas compartilhando o link com o aplicativo.
* **Organização Automática em Pastas:** Os arquivos são salvos diretamente em `Download/GuardiaoMobile/Videos`, `Fotos` ou `Audios`, sem necessidade de gerenciamento manual.
* **Extrator de Áudio Local:** Separe rapidamente a trilha de áudio (.mp3) de qualquer arquivo de vídeo (.mp4, .mkv, etc.) armazenado no aparelho usando o FFmpeg integrado.

## 🛠️ Tecnologias Utilizadas

* **Linguagem:** Kotlin
* **Interface:** Jetpack Compose (Material Design 3)
* **Rede & DNS:** OkHttp (DoH - DNS over HTTPS)
* **Processamento de Mídia:** FFmpeg (`com.yausername.ffmpeg`)
* **Extração Web:** yt-dlp-android (`io.github.junkfood02.youtubedl-android`)
* **Arquitetura:** MVVM (Model-View-ViewModel) com Coroutines e Flows
* **Compatibilidade:** Android 7.0+ (API 24+) a Android 15. Suporte a arquiteturas `arm64-v8a`, `armeabi-v7a`, `x86` e `x86_64`.

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
