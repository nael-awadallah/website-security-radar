jQuery(function ($) {
	function replaceResultsContent(html) {
		const parser = new window.DOMParser();
		const doc = parser.parseFromString(html, 'text/html');
		const nextContent = doc.querySelector('#wsr-results-content');
		const currentContent = document.querySelector('#wsr-results-content');

		if (!nextContent || !currentContent) {
			window.location.reload();
			return;
		}

		currentContent.replaceWith(nextContent);
		const nextPanel = document.querySelector('#wsr-change-details-panel');

		if (nextPanel) {
			window.setTimeout(function () {
				nextPanel.focus();
				nextPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
			}, 50);
		}
	}

	function loadResults(url, pushState) {
		const targetUrl = new URL(url, window.location.origin);
		const resultsContent = document.querySelector('#wsr-results-content');

		if (!resultsContent) {
			window.location.href = targetUrl.toString();
			return;
		}

		resultsContent.classList.add('wsr-loading');

		window.fetch(targetUrl.toString(), {
			credentials: 'same-origin',
			headers: {
				'X-Requested-With': 'XMLHttpRequest'
			}
		}).then(function (response) {
			if (!response.ok) {
				throw new Error('Request failed');
			}

			return response.text();
		}).then(function (html) {
			replaceResultsContent(html);
			if (pushState) {
				window.history.pushState({}, '', targetUrl.toString());
			}
		}).catch(function () {
			window.location.href = targetUrl.toString();
		}).finally(function () {
			const updatedContent = document.querySelector('#wsr-results-content');
			if (updatedContent) {
				updatedContent.classList.remove('wsr-loading');
			}
		});
	}

	function runAction(actionKey, $button) {
		const isScan = actionKey === 'scan';
		const ajaxAction = isScan ? wsrAdmin.scanAction : wsrAdmin.baselineAction;
		const loadingText = isScan ? wsrAdmin.strings.scanning : wsrAdmin.strings.baselining;
		const originalText = $button.text();
		const requestData = {
			action: ajaxAction,
			nonce: wsrAdmin.nonce
		};

		if (!isScan) {
			requestData.label = $('#wsr-baseline-label').val() || '';
		}

		$button.addClass('wsr-loading').prop('disabled', true).text(loadingText);

		$.post(wsrAdmin.ajaxUrl, requestData).done(function (response) {
			if (response && response.success) {
				window.alert(response.data.message || wsrAdmin.strings.success);
				window.location.reload();
				return;
			}

			window.alert((response && response.data && response.data.message) || wsrAdmin.strings.error);
		}).fail(function () {
			window.alert(wsrAdmin.strings.error);
		}).always(function () {
			$button.removeClass('wsr-loading').prop('disabled', false).text(originalText);
		});
	}

	$(document).on('click', '.wsr-ajax-button', function () {
		const $button = $(this);
		runAction($button.data('wsr-action'), $button);
	});

	$(document).on('submit', '#wsr-filter-form', function (event) {
		if (!window.fetch || !window.DOMParser) {
			return;
		}

		event.preventDefault();

		const form = event.currentTarget;
		const formData = new window.FormData(form);
		const url = new URL(form.action || window.location.href, window.location.origin);

		formData.forEach(function (value, key) {
			if (value) {
				url.searchParams.set(key, value.toString());
			} else {
				url.searchParams.delete(key);
			}
		});

		url.searchParams.delete('paged');
		loadResults(url.toString(), true);
	});

	$(document).on('click', '#wsr-reset-filters, .wsr-group-card, .tablenav-pages a', function (event) {
		if (!window.fetch || !window.DOMParser) {
			return;
		}

		const href = $(this).attr('href');

		if (!href) {
			return;
		}

		event.preventDefault();
		loadResults(href, true);
	});

	$(document).on('change', '#wsr-filter-severity, #wsr-filter-type, #wsr-filter-date-from, #wsr-filter-date-to, #wsr-filter-review-status', function () {
		if (!window.fetch || !window.DOMParser) {
			return;
		}

		$('#wsr-filter-form').trigger('submit');
	});

	let pathSearchTimer = null;

	$(document).on('input', '#wsr-filter-path', function () {
		if (!window.fetch || !window.DOMParser) {
			return;
		}

		window.clearTimeout(pathSearchTimer);
		pathSearchTimer = window.setTimeout(function () {
			$('#wsr-filter-form').trigger('submit');
		}, 250);
	});

	$(window).on('popstate', function () {
		if (!window.fetch || !window.DOMParser) {
			return;
		}

		loadResults(window.location.href, false);
	});

	const $changeDetailsPanel = $('#wsr-change-details-panel');

	if ($changeDetailsPanel.length) {
		window.setTimeout(function () {
			$changeDetailsPanel.trigger('focus')[0].scrollIntoView({ behavior: 'smooth', block: 'start' });
		}, 50);
	}
});
