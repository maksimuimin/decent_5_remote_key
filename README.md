# Технопарк Mail.ru, Разработчик децентрализованных систем, Домашнее задание №5
## Уймин Максим Сергеевич

Сделать программу - консольное приложение, используя языки: С/C++, Rust, Python, Go, Node.JS.
Код должен быть оформлен в  отдельный репозитарий на GitHub c инструкцией в README.md как собрать и запустить код в консоли под Ubuntu 18.04.
К заданию должен быть приложен скриншот или текст вывода одного или нескольких прогонов программы(!).

Программа эмулирует работу автомобильного брелока, открывающего машину, с использованием ЭЦП в условиях, когда канал связи полностью доступен любому прослушивающему
(в том числе и в течение большого времени и попыток), также атакующий может повторить прослушанные данные.

## Как запустить
`go build -o bin/rke cmd/main.go` - сборка исполняемого файла. Требуется компилятор Go версии >= 1.15, при необходимости версию можно понизить в файле go.mod, должно собираться начиная с версии 1.13

`./bin/rke` - выполнить программу

## Демонстрация работы
TODO

## Принцип работы
Пакет `netemu` эмулирует работу сети, позволяет гонять структуры (пакеты) между потоками, поддерживает broadcast рассылку сообщений всем нодам сети.
В реальности ключ использовал бы открытый радио канал, это фактически то же самое, что broadcast.

Пакет `proto` реализует протокол общения ключа и машины.

Я решил не выделять различные роли на уровне протокола, так что машина и ключ с точки зрения протокола равноправны.
Это позволяет отправить любую команду к действию как с ключа машине, так и с машины ключу.

Выполнение любой команды работает за 3 отправки пакета:
```
Peer1 -> Peer2 [PROTO_REQ_ACTION]: отправляется команда к действию и челлендж от Peer1
Peer1 <- Peer2 [PROTO_REQ_CHALLENGE]: отправляется решение челленджа от Peer1 и челлендж от Peer2, Peer1 убеждается, что команду принял правильный адресат
Peer1 -> Peer2 [PROTO_REQ_PROOF]: отправляется решение челленджа от Peer2, Peer2 убеждается, что команду отправил правильный адресант, Peer2 выполняет команду
```

От каждого пакета берётся md5 хеш и подписывается электронной подписью, основанной на эллиптических кривых. Для подписи используется кривая `secp256r1`.
Публичные ключи для проверки ЭЦП загружаются в машину и ключ перед началом работы (в реальном мире, это происходило бы на заводе)

Челлендж представляет из себя рандомное число. Решение челленджа - вернуть это же самое число, подписанное своей ЭЦП.
Для реализации рандома во всей программе используется источник энтропии, предоставленный операционной системой. Из документации к golang:

> On Linux and FreeBSD, Reader uses getrandom(2) if available, /dev/urandom otherwise. On OpenBSD, Reader uses getentropy(2). On other Unix-like systems, Reader reads from /dev/urandom.
> On Windows systems, Reader uses the RtlGenRandom API. On Wasm, Reader uses the Web Crypto API.
