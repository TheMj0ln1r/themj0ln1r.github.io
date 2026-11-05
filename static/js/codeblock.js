// Adds a header bar (file name or language, plus a copy button) to highlighted code blocks.
(function () {
    const LABELS = { shellscript: "shell", plain: "text", javascript: "js", typescript: "ts", python: "py" };

    const copyIcon = '<svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"/></svg>';
    const doneIcon = '<svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>';

    function codeText(code) {
        const clone = code.cloneNode(true);
        clone.querySelectorAll(".giallo-ln").forEach((n) => n.remove());
        return clone.textContent.replace(/\n$/, "");
    }

    document.querySelectorAll("pre.giallo").forEach((pre) => {
        const code = pre.querySelector("code");
        if (!code) return;

        const name = pre.dataset.name || code.dataset.name;
        const lang = (code.dataset.lang || "plain").toLowerCase();

        const bar = document.createElement("div");
        bar.className = "code-bar";

        const label = document.createElement("span");
        label.className = "code-label";
        label.textContent = name || LABELS[lang] || lang;

        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "code-copy";
        btn.setAttribute("aria-label", "Copy code");
        btn.innerHTML = copyIcon;
        btn.addEventListener("click", async () => {
            try {
                await navigator.clipboard.writeText(codeText(code));
                btn.innerHTML = doneIcon;
                setTimeout(() => (btn.innerHTML = copyIcon), 1500);
            } catch (e) {
                console.error("Copy failed", e);
            }
        });

        bar.append(label, btn);
        pre.prepend(bar);
        pre.classList.add("has-bar");
    });
})();
