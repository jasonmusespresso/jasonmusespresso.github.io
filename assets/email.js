// Build mailto: links from the reversed address in data-r, so the plain
// address never appears in the page source that scrapers read.
document.querySelectorAll('a.email[data-r]').forEach(function (a) {
  a.href = 'mailto:' + a.getAttribute('data-r').split('').reverse().join('');
});
