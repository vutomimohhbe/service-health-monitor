(function () {
  const serviceInput = document.querySelector('#ticket-form [name="service"]');
  const suggestions = document.getElementById("duplicate-suggestions");
  if (!serviceInput || !suggestions) return;

  let timer;
  let requestId = 0;

  function showMessage(message) {
    suggestions.replaceChildren();
    const text = document.createElement("p");
    text.textContent = message;
    suggestions.appendChild(text);
    suggestions.hidden = false;
  }

  serviceInput.addEventListener("input", function () {
    clearTimeout(timer);
    const service = serviceInput.value.trim();
    const currentRequest = ++requestId;
    if (!service) {
      suggestions.hidden = true;
      suggestions.replaceChildren();
      return;
    }

    timer = setTimeout(async function () {
      try {
        const response = await fetch(
          "/api/tickets/suggestions?service=" + encodeURIComponent(service),
          { credentials: "same-origin" }
        );
        if (!response.ok) throw new Error(`Suggestion request failed (${response.status})`);
        const data = await response.json();
        if (currentRequest !== requestId) return;
        suggestions.replaceChildren();
        if (!data.suggestions.length) {
          suggestions.hidden = true;
          return;
        }

        const heading = document.createElement("p");
        heading.textContent = "Open tickets already exist for this service:";
        const list = document.createElement("ul");
        data.suggestions.forEach(function (ticket) {
          const item = document.createElement("li");
          item.textContent = `${ticket.reference} · ${ticket.status} · ${ticket.created_at} UTC`;
          list.appendChild(item);
        });
        suggestions.append(heading, list);
        suggestions.hidden = false;
      } catch (error) {
        if (currentRequest === requestId) {
          showMessage("Unable to check for existing tickets right now.");
        }
        console.error("Unable to check for similar service tickets.", error);
      }
    }, 300);
  });
})();
