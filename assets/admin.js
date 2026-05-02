jQuery(function ($) {
	function showNotice(message, type) {
		const noticeClass = type === 'success' ? 'notice-success' : 'notice-error';
		const $wrap = $('.wsr-wrap').first();

		if (!$wrap.length) {
			return;
		}

		$wrap.find('.wsr-runtime-notice').remove();

		const $notice = $('<div />', {
			class: 'notice is-dismissible wsr-runtime-notice ' + noticeClass
		});
		const $content = $('<p />').text(message);
		const $dismiss = $('<button />', {
			type: 'button',
			class: 'notice-dismiss'
		}).append($('<span />', {
			class: 'screen-reader-text',
			text: 'Dismiss this notice.'
		}));

		$dismiss.on('click', function () {
			$notice.remove();
		});

		$notice.append($content, $dismiss);
		$wrap.prepend($notice);

		window.setTimeout(function () {
			$notice[0].scrollIntoView({ behavior: 'smooth', block: 'start' });
		}, 10);
	}

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
		const isVulnerability = actionKey === 'vulnerability';
		const ajaxAction = isScan ? wsrAdmin.scanAction : (isVulnerability ? wsrAdmin.vulnerabilityAction : wsrAdmin.baselineAction);
		const loadingText = isScan ? wsrAdmin.strings.scanning : (isVulnerability ? wsrAdmin.strings.vulnerabilityChecking : wsrAdmin.strings.baselining);
		const originalText = $button.text();
		const $actionsCard = $button.closest('[data-wsr-actions-card]');
		const $actionButtons = $actionsCard.find('.wsr-ajax-button');
		const $actionInputs = $actionsCard.find('input, button');
		const requestData = {
			action: ajaxAction,
			nonce: wsrAdmin.nonce
		};

		if (!isScan && !isVulnerability) {
			requestData.label = $('#wsr-baseline-label').val() || '';
		}

		$actionsCard.addClass('wsr-loading');
		$actionInputs.prop('disabled', true);
		$actionButtons.each(function () {
			const $currentButton = $(this);
			$currentButton.data('wsr-original-text', $currentButton.text());
		});
		$button.addClass('wsr-loading').text(loadingText);

		$.post(wsrAdmin.ajaxUrl, requestData).done(function (response) {
			if (response && response.success) {
				showNotice(response.data.message || wsrAdmin.strings.success, 'success');
				window.setTimeout(function () {
					window.location.reload();
				}, 900);
				return;
			}

			showNotice((response && response.data && response.data.message) || wsrAdmin.strings.error, 'error');
		}).fail(function () {
			showNotice(wsrAdmin.strings.error, 'error');
		}).always(function () {
			$actionsCard.removeClass('wsr-loading');
			$actionInputs.prop('disabled', false);
			$actionButtons.each(function () {
				const $currentButton = $(this);
				const currentOriginalText = $currentButton.data('wsr-original-text');
				if (currentOriginalText) {
					$currentButton.text(currentOriginalText);
				}
				$currentButton.removeClass('wsr-loading').removeData('wsr-original-text');
			});
			$button.text(originalText);
		});
	}

	$(document).on('click', '.wsr-ajax-button', function () {
		const $button = $(this);
		runAction($button.data('wsr-action'), $button);
	});

	$(document).on('click', '.wsr-issue-toggle', function () {
		const $button = $(this);
		const targetId = $button.attr('data-wsr-toggle-target');
		const $target = $('#' + targetId);

		if (!$target.length) {
			return;
		}

		const isExpanded = $button.attr('aria-expanded') === 'true';

		$button.attr('aria-expanded', isExpanded ? 'false' : 'true');
		$button.text(isExpanded ? wsrAdmin.strings.showDetails : wsrAdmin.strings.hideDetails);
		$target.prop('hidden', isExpanded);
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

		if (!form.querySelector('#wsr-filter-new-only:checked')) {
			url.searchParams.delete('new_only');
		}

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

	$(document).on('change', '#wsr-filter-severity, #wsr-filter-type, #wsr-filter-date-from, #wsr-filter-date-to, #wsr-filter-review-status, #wsr-filter-confidence, #wsr-filter-new-only', function () {
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
