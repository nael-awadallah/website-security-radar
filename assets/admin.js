jQuery(function ($) {
	function runAction(actionKey, $button) {
		const isScan = actionKey === 'scan';
		const ajaxAction = isScan ? wsrAdmin.scanAction : wsrAdmin.baselineAction;
		const loadingText = isScan ? wsrAdmin.strings.scanning : wsrAdmin.strings.baselining;
		const originalText = $button.text();

		$button.addClass('wsr-loading').prop('disabled', true).text(loadingText);

		$.post(wsrAdmin.ajaxUrl, {
			action: ajaxAction,
			nonce: wsrAdmin.nonce
		}).done(function (response) {
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
});
