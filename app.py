import io
import zipfile
from pathlib import PurePosixPath

import streamlit as st

from dmgd_core import process_files

st.set_page_config(page_title="DMGD 云端安全解析", layout="wide")
st.title("DMGD 云端安全解析")
st.write("原新气象数据解密小程序的网页安全版：上传副本、内存解析、校验后下载，不移动或删除源文件。")

with st.expander("支持范围与处理规则", expanded=False):
    st.markdown(
        "- 支持明文 DMGD，以及原程序使用的 DES/ECB/NoPadding 加密 DMGD。\n"
        "- 可上传多个 `.dat`，或上传包含它们的 `.zip`；ZIP 不解压到磁盘，只读取 DMGD 条目。\n"
        "- 校验行尾校验和、掩码与字段数；`*`、`-`、`/` 按缺测输出为空。\n"
        "- 当前版本只处理本批数据已出现的 DMGD 要素；遇到未映射要素会停止，不会静默丢列。\n"
        "- `WXNo1.02` 等是层号，不自动猜测对应的测风高度。"
    )

upload_signature = [(file.name, file.size) for file in st.session_state.get("uploads") or []]
if st.session_state.get("upload_signature") != upload_signature:
    st.session_state.pop("result", None)
    st.session_state["upload_signature"] = upload_signature

uploads = st.file_uploader(
    "上传 DMGD 文件或 ZIP",
    type=["dat", "zip"],
    accept_multiple_files=True,
    key="uploads",
    help="上传的是副本；网页不会接触你电脑上的原始目录。",
)

col1, col2 = st.columns(2)
with col1:
    des_password = st.text_input(
        "DES 密码（仅密文需要）",
        type="password",
        key="des_password",
        help="只用于本次会话的内存解密，不写入结果或应用配置。",
    )
with col2:
    deduplicate = st.checkbox("去除完全重复记录", value=True)

with st.expander("原 Windows 编码设置", expanded=False):
    enc1, enc2 = st.columns(2)
    with enc1:
        password_encoding = st.selectbox("DES 密码编码", ["gbk", "utf-8"], index=0)
    with enc2:
        text_encoding = st.selectbox("解密后文本编码", ["gbk", "utf-8"], index=0)


def read_uploads(files):
    payloads = []
    skipped = []
    total_uncompressed = 0
    for uploaded in files:
        if uploaded.name.lower().endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(uploaded.getvalue())) as archive:
                infos = [info for info in archive.infolist() if not info.is_dir()]
                total_uncompressed += sum(info.file_size for info in infos)
                if total_uncompressed > 1_000_000_000:
                    raise ValueError("ZIP 解压后总大小超过 1 GB，请分批上传")
                for info in infos:
                    basename = PurePosixPath(info.filename).name
                    source_name = f"{uploaded.name}!{info.filename}"
                    if basename.upper().startswith("DMGD") and basename.lower().endswith(".dat"):
                        payloads.append((source_name, archive.read(info)))
                    else:
                        skipped.append(source_name)
        else:
            basename = PurePosixPath(uploaded.name).name
            if basename.upper().startswith("DMGD") and basename.lower().endswith(".dat"):
                payloads.append((basename, uploaded.getvalue()))
            else:
                skipped.append(basename)
    return payloads, skipped


if uploads:
    st.caption(f"已选择 {len(uploads)} 个上传文件；点击按钮后才开始读取和解析。")
st.caption("文件将发送至 Streamlit Cloud 处理；请勿上传涉密数据。公开代码仓库不包含任何测风样例。")

if st.button("开始安全解析", type="primary", disabled=not uploads):
    st.session_state.pop("result", None)
    try:
        with st.spinner("正在校验并生成 CSV，请不要关闭页面……"):
            payloads, skipped = read_uploads(uploads)
            result = process_files(
                payloads,
                des_password=des_password,
                password_encoding=password_encoding,
                text_encoding=text_encoding,
                deduplicate=deduplicate,
                skipped=skipped,
            )
        st.session_state["result"] = result
        st.success("解析完成；所有通过校验的记录已打包。")
    except Exception as exc:
        st.error(f"处理已中止，未生成结果：{exc}")

result = st.session_state.get("result")
if result:
    stats = result["stats"]
    metric1, metric2, metric3, metric4 = st.columns(4)
    metric1.metric("DMGD 文件", stats["files"])
    metric2.metric("输出记录", stats["written"])
    metric3.metric("重复记录", stats["duplicates"])
    metric4.metric("DES 解密文件", stats["decrypted_files"])
    if result["skipped"]:
        with st.expander(f"已跳过 {len(result['skipped'])} 个非 DMGD 文件", expanded=False):
            st.write("\n".join(result["skipped"][:200]))
    st.download_button(
        "下载 CSV 与校验报告（ZIP）",
        data=result["archive"],
        file_name="DMGD解析结果-Kimi.zip",
        mime="application/zip",
        type="primary",
    )
    st.subheader("前 200 条输出预览")
    st.dataframe(result["preview"], use_container_width=True, hide_index=True)
    with st.expander("完整处理报告", expanded=False):
        st.text(result["report"])

if st.button("清除结果与密码"):
    for key in ["result", "des_password"]:
        st.session_state.pop(key, None)
    st.rerun()

st.caption("不缓存上传数据，不保存密码，不生成 hprof、logs 或 storage；云端会话资源由平台按生命周期回收。")
