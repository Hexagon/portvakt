// Copy-to-clipboard buttons: <button data-copy="element-id">.
for (const btn of document.querySelectorAll("button[data-copy]")) {
  btn.addEventListener("click", async () => {
    const text = document.getElementById(btn.dataset.copy)?.textContent || "";
    try {
      await navigator.clipboard.writeText(text);
      btn.textContent = "Copied";
    } catch {
      btn.textContent = "Select & copy";
    }
    setTimeout(() => { btn.textContent = "Copy"; }, 1500);
  });
}
