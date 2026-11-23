(() => {
  const controls = document.getElementById("coverage-controls");
  const query = document.getElementById("coverage-query");
  const gaps = document.getElementById("coverage-gaps");
  const count = document.getElementById("coverage-count");
  const cases = Array.from(document.querySelectorAll("#coverage-table tbody tr"), row => ({
    row,
    text: Array.from(row.cells, cell => cell.textContent).join(" ").toLowerCase(),
    hasGap: row.cells[row.cells.length - 1].textContent.trim() !== "—",
  }));
  if (!cases.length) return;

  function filterCases() {
    const terms = query.value.toLowerCase().trim().split(/\s+/);
    let visible = 0;
    for (const item of cases) {
      item.row.hidden = (gaps.checked && !item.hasGap) || !terms.every(term => item.text.includes(term));
      if (!item.row.hidden) visible++;
    }
    count.textContent = visible ? `${visible} of ${cases.length} cases` : "No matching cases";
  }

  query.addEventListener("input", filterCases);
  gaps.addEventListener("change", filterCases);
  filterCases();
  controls.hidden = false;
})();
