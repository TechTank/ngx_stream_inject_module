# ngx\_stream\_inject\_module

![logo](https://github.com/user-attachments/assets/d0bee57f-5316-4aca-9bfa-8f1e947f614a)

`ngx_stream_inject_module` is a custom NGINX stream module that allows you to inject data into a TCP connection **immediately after** the upstream connection is established.

---

## 🚀 Features

* Inject custom strings (or variable-based strings) into stream connections
* Hook into the upstream socket’s write handler
* Works seamlessly with the NGINX stream module
* Supports dynamic values using NGINX variables
* Configurable maximum injection length and retry defer count
* Supports injection after upstream handshake (including TLS detection)

---

## 🔧 Configuration Example

### Basic Injection:

```nginx
stream {
    inject_enable       on;
    inject_max_length   1024;

    server {
        listen          12345;
        proxy_pass      backend;

        inject_enable   on;
        inject_string   "USER anonymous\r\n";
    }
}
```

### Advanced Injection with Variables:

```nginx
stream {
    inject_enable       on;
    inject_max_length   2048;

    server {
        listen          2222;
        proxy_pass      backend;

        inject_enable   on;
        inject_string   "NGINX: {\"ip\":\"$remote_addr\",\"sni\":\"$ssl_server_name\"}\r\n";
    }
}
```

---

## ⚙️ Directives

| Directive           | Context     | Description                               |
| ------------------- | ----------- | ----------------------------------------- |
| `inject_enable`     | main/server | Enables injection on this level (on/off)  |
| `inject_max_length` | main/server | Maximum allowed injection string length   |
| `inject_string`     | server      | The string to inject (supports variables) |

---

## 🛠 Build Instructions

```bash
git clone https://github.com/TechTank/ngx_stream_inject_module.git
cd nginx-<version>

./configure \
  --add-module=/path/to/ngx_stream_inject_module \
  --with-stream

make && sudo make install
```

To use with [OpenResty](https://openresty.org/):

```bash
./configure \
  --add-module=/path/to/ngx_stream_inject_module
```

---

## ℹ️ Behavior and Considerations

* **Timing**: The injection occurs after the upstream TCP handshake is complete.
* **TLS Streams**: Injection operates at the TCP layer and can be used with both encrypted and unencrypted streams. If the upstream is using TLS, the injection is delayed until the TLS handshake completes, ensuring compatibility.
* **Variables**: You can use NGINX variables in the `inject_string`, such as `$remote_addr`, `$ssl_preread_server_name`, etc.
* **Limits**: Be sure to set `inject_max_length` high enough to accommodate your longest payloads. Oversized injections are silently discarded.

---

## 📂 Project Structure

* `ngx_stream_inject_module.c` – Main logic, hooks, config handling
* `ngx_stream_inject_module.h` – Context, configuration, and public API

---

## 🧑‍💻 Author

Created by [Brogan Scott Houston McIntyre (TechTank)](https://github.com/TechTank)

---

## 📄 License

This module is free for **personal and educational use**.

**Commercial use requires a separate commercial license.** Please contact [TechTank](https://github.com/TechTank) for details.

```text
Copyright (c) 2024 TechTank

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to use
the Software for personal, non-commercial, or educational purposes.

Commercial use, including use in proprietary software, SaaS platforms,
or services offered to third parties, is **not** permitted without a valid
commercial license.
```
