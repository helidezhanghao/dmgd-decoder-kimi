import csv
import hashlib
import io
import re
import zipfile
from collections import defaultdict
from datetime import datetime, timedelta
from decimal import Decimal

FIELD_NAMES = {
    1: "ave_wd_2min_deg",
    2: "ave_ws_2min_m_s",
    3: "ave_wd_10min_deg",
    4: "ave_ws_10min_m_s",
    5: "most_wd_deg",
    6: "most_ws_m_s",
    7: "most_ws_time",
    8: "inst_wd_deg",
    9: "inst_ws_m_s",
    10: "max_wd_deg",
    11: "max_ws_m_s",
    12: "max_ws_time",
    15: "temp_c",
    16: "max_temp_c",
    17: "max_temp_time",
    18: "min_temp_c",
    19: "min_temp_time",
    20: "wet_bulb_temp_c",
    21: "relative_humidity_pct",
    22: "min_relative_humidity_pct",
    23: "min_relative_humidity_time",
    24: "vapor_pressure_hpa",
    25: "dew_point_temp_c",
    26: "pressure_hpa",
    27: "max_pressure_hpa",
    28: "max_pressure_time",
    29: "min_pressure_hpa",
    30: "min_pressure_time",
    62: "ave_ws_10min_stddev_m_s",
    67: "sea_level_pressure_hpa",
    110: "pressure_change_3h_hpa",
    111: "pressure_change_24h_hpa",
    112: "temp_change_24h_c",
    113: "max_temp_24h_c",
    114: "min_temp_24h_c",
}
INTEGER_FIELDS = {1, 3, 5, 8, 10, 21, 22}
FLOAT_1_FIELDS = {2, 4, 6, 9, 11, 15, 16, 18, 20, 24, 25, 26, 27, 29, 67, 110, 111, 112, 113, 114}
FLOAT_2_FIELDS = {62}
TIME_FIELDS = {7, 12, 17, 19, 23, 28, 30}
BASE_COLUMNS = ["observation_time", "layer", "source_file", "source_line"]


def mask_positions(mask):
    if re.fullmatch(r"[01]+", mask):
        bits = mask
    elif re.fullmatch(r"[0-9A-Fa-f]+", mask):
        bits = "".join(f"{int(char, 16):04b}" for char in mask)
    else:
        raise ValueError(f"非法掩码: {mask!r}")
    return [index + 1 for index, bit in enumerate(bits) if bit == "1"]


def des_decrypt(data, password, password_encoding="gbk"):
    key = password.encode(password_encoding)
    if len(key) < 8:
        raise ValueError("DES 密码编码后至少需要 8 字节")
    if len(data) % 8:
        raise ValueError(f"DES 密文长度必须是 8 的倍数，实际为 {len(data)}")
    key = key[:8]
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise RuntimeError("DES 解密需要 cryptography；明文 DMGD 不需要它") from exc
    if hasattr(algorithms, "DES"):
        algorithm = algorithms.DES(key)
    else:
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        except ImportError:
            TripleDES = algorithms.TripleDES
        algorithm = TripleDES(key * 3)
    decryptor = Cipher(algorithm, modes.ECB()).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def convert_value(index, raw, observation_time):
    if raw in {"*", "-", "/"}:
        return ""
    if index in TIME_FIELDS:
        if not re.fullmatch(r"\d{4}", raw):
            raise ValueError(f"非法 HHmm 时间: {raw!r}")
        event_time = observation_time.replace(hour=int(raw[:2]), minute=int(raw[2:]))
        if event_time > observation_time:
            event_time -= timedelta(days=1)
        return event_time.strftime("%Y-%m-%d %H:%M")
    if index in INTEGER_FIELDS:
        return str(int(raw))
    if index in FLOAT_1_FIELDS:
        return format(Decimal(raw) / 10, "f")
    if index in FLOAT_2_FIELDS:
        return format(Decimal(raw) / 100, "f")
    return raw


def parse_line(raw, source_file, source_line, text_encoding):
    try:
        before, checksum_text = raw.rsplit(b"*", 1)
        if len(checksum_text) != 2:
            raise ValueError("行尾校验码不是两位十六进制")
        expected = int(checksum_text, 16)
    except (ValueError, UnicodeError) as exc:
        raise ValueError(f"{source_file}:{source_line}: 行尾校验码格式错误: {exc}") from exc
    actual = sum(before.rstrip()) & 0xFF
    if actual != expected:
        raise ValueError(f"{source_file}:{source_line}: 校验和不符，计算 {actual:02X}，原值 {expected:02X}")
    try:
        parts = before.decode(text_encoding).split()
        if len(parts) < 5 or parts[0] != "DMGD":
            raise ValueError("不是 DMGD 记录")
        observation_time = datetime.strptime(f"{parts[2]} {parts[3]}", "%Y-%m-%d %H:%M")
        positions = mask_positions(parts[4])
        values = parts[5:]
        if len(positions) != len(values):
            raise ValueError(f"掩码有效位 {len(positions)} 个，字段值 {len(values)} 个")
        record = {
            "observation_time": observation_time.strftime("%Y-%m-%d %H:%M"),
            "layer": parts[1],
            "source_file": source_file,
            "source_line": source_line,
        }
        for index, raw_value in zip(positions, values):
            if index not in FIELD_NAMES:
                raise ValueError(f"尚未映射的要素索引 {index}，未静默丢弃")
            record[FIELD_NAMES[index]] = convert_value(index, raw_value, observation_time)
        return record
    except (ValueError, UnicodeError) as exc:
        raise ValueError(f"{source_file}:{source_line}: {exc}") from exc


def prepare_data(data, source_name, des_password, password_encoding, text_encoding):
    if data.startswith(b"DMGD "):
        return data, False
    if not des_password:
        raise ValueError(f"{source_name}: 不是明文 DMGD；如为 DES 密文，请填写密码")
    try:
        decrypted = des_decrypt(data, des_password, password_encoding).rstrip(b"\x00")
    except Exception as exc:
        raise ValueError(f"{source_name}: DES 解密失败，请检查密码和文件格式: {exc}") from exc
    if not decrypted.startswith(b"DMGD "):
        raise ValueError(f"{source_name}: DES 解码后仍不是 DMGD，已停止")
    decrypted.decode(text_encoding)
    return decrypted, True


def iter_records(data, source_name, text_encoding):
    for source_line, raw in enumerate(data.splitlines(), 1):
        if raw.strip():
            yield parse_line(raw, source_name, source_line, text_encoding), raw


def build_report(stats, layer_stats, file_reports, skipped):
    lines = [
        "DMGD 云端安全解析报告",
        "",
        f"输入 DMGD 文件: {stats['files']} 个",
        f"DES 解密文件: {stats['decrypted_files']} 个",
        f"输入记录: {stats['records']} 条",
        f"输出记录: {stats['written']} 条",
        f"完全重复记录: {stats['duplicates']} 条" + ("（已去重）" if stats["deduplicate"] else "（保留）"),
        f"跳过非 DMGD 文件: {len(skipped)} 个",
        "校验和、掩码位数、字段数量和数值转换: 全部通过",
        "源文件处理: 仅在内存读取上传副本，不移动、不覆盖、不删除",
        "密码处理: 不写入输出、配置或日志",
        "",
        "各层输出记录:",
    ]
    for layer in sorted(layer_stats):
        item = layer_stats[layer]
        lines.append(f"- {layer}: {item['count']} 条；{item['first']} 至 {item['last']}")
    lines.extend(["", "源文件 SHA-256（对上传原 bytes 计算，DES 文件按密文计算）:"])
    for item in file_reports:
        lines.append(f"- {item['name']} | {item['sha256']} | {item['records']} 条 | DES={item['decrypted']}")
    if skipped:
        lines.extend(["", "跳过文件（不计入解析结果）:"])
        lines.extend(f"- {name}" for name in skipped[:200])
        if len(skipped) > 200:
            lines.append(f"- 其余 {len(skipped) - 200} 个未展开")
    lines.extend([
        "",
        "说明: WXNo1、WXNo1.02 等是文件内层号，不等于物理高度；高度名称须按测风塔配置另行确认。",
        "说明: *、-、/ 按缺测输出为空；同一层同一时间但内容不同的记录会中止处理。",
    ])
    return "\n".join(lines)


def process_files(payloads, des_password="", password_encoding="gbk", text_encoding="gbk", deduplicate=True, skipped=None):
    skipped = skipped or []
    output = io.BytesIO()
    seen = {}
    preview = []
    file_reports = []
    layer_stats = defaultdict(lambda: {"count": 0, "first": None, "last": None})
    stats = {"files": 0, "decrypted_files": 0, "records": 0, "written": 0, "duplicates": 0, "deduplicate": deduplicate}
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        with archive.open("DMGD解析结果-Kimi.csv", "w") as raw_csv:
            with io.TextIOWrapper(raw_csv, encoding="utf-8-sig", newline="") as text_csv:
                writer = csv.DictWriter(text_csv, fieldnames=BASE_COLUMNS + list(FIELD_NAMES.values()), extrasaction="ignore")
                writer.writeheader()
                for source_name, uploaded_bytes in payloads:
                    stats["files"] += 1
                    data, decrypted = prepare_data(uploaded_bytes, source_name, des_password, password_encoding, text_encoding)
                    stats["decrypted_files"] += int(decrypted)
                    file_records = 0
                    for record, raw in iter_records(data, source_name, text_encoding):
                        stats["records"] += 1
                        file_records += 1
                        key = (record["layer"], record["observation_time"])
                        digest = hashlib.sha256(raw).digest()
                        if key in seen:
                            if seen[key] != digest:
                                raise ValueError(f"{source_name}:{record['source_line']}: 同一层同一时间存在内容冲突: {key}")
                            stats["duplicates"] += 1
                            if deduplicate:
                                continue
                        else:
                            seen[key] = digest
                        writer.writerow(record)
                        stats["written"] += 1
                        layer = layer_stats[record["layer"]]
                        layer["count"] += 1
                        timestamp = record["observation_time"]
                        layer["first"] = timestamp if layer["first"] is None else min(layer["first"], timestamp)
                        layer["last"] = timestamp if layer["last"] is None else max(layer["last"], timestamp)
                        if len(preview) < 200:
                            preview.append(record)
                    file_reports.append({
                        "name": source_name,
                        "sha256": hashlib.sha256(uploaded_bytes).hexdigest(),
                        "records": file_records,
                        "decrypted": decrypted,
                    })
        if not stats["files"]:
            raise ValueError("上传内容中未找到 DMGD*.dat")
        report = build_report(stats, layer_stats, file_reports, skipped)
        archive.writestr("处理报告-Kimi.txt", report.encode("utf-8-sig"))
    return {"archive": output.getvalue(), "preview": preview, "report": report, "stats": stats, "skipped": skipped}
