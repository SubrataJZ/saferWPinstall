<?php
/**
 * Plugin Name: SaferWP Agent
 * Description: Lightweight agent that reports this site's installed plugins/themes to a SaferWP Install dashboard, and accepts scan commands from it.
 * Version: 1.0.0
 * Author: SaferWP Install
 */

if (!defined('ABSPATH')) {
    exit;
}

define('SAFERWP_AGENT_OPTION_KEY', 'saferwp_agent_api_key');
define('SAFERWP_AGENT_OPTION_ENABLED', 'saferwp_agent_scan_enabled');

/**
 * Admin settings screen: shows/regenerates the API key the dashboard uses to authenticate,
 * and a toggle mirroring the dashboard's start/stop scan state for visibility on this site.
 */
add_action('admin_menu', function () {
    add_options_page(
        'SaferWP Agent',
        'SaferWP Agent',
        'manage_options',
        'saferwp-agent',
        'saferwp_agent_render_settings_page'
    );
});

function saferwp_agent_get_or_create_api_key() {
    $key = get_option(SAFERWP_AGENT_OPTION_KEY);
    if (!$key) {
        $key = wp_generate_password(40, false, false);
        update_option(SAFERWP_AGENT_OPTION_KEY, $key);
    }
    return $key;
}

function saferwp_agent_render_settings_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    if (isset($_POST['saferwp_regenerate']) && check_admin_referer('saferwp_agent_settings')) {
        update_option(SAFERWP_AGENT_OPTION_KEY, wp_generate_password(40, false, false));
        echo '<div class="updated"><p>API key regenerated. Update it in the SaferWP dashboard.</p></div>';
    }

    $key = saferwp_agent_get_or_create_api_key();
    $enabled = get_option(SAFERWP_AGENT_OPTION_ENABLED, '1');
    $endpoint = rest_url('saferwp/v1/inventory');
    ?>
    <div class="wrap">
        <h1>SaferWP Agent</h1>
        <p>Add this site to your SaferWP Install dashboard using the details below.</p>
        <table class="form-table">
            <tr>
                <th>Site URL</th>
                <td><code><?php echo esc_html(home_url()); ?></code></td>
            </tr>
            <tr>
                <th>Inventory endpoint</th>
                <td><code><?php echo esc_html($endpoint); ?></code></td>
            </tr>
            <tr>
                <th>API key</th>
                <td><code><?php echo esc_html($key); ?></code></td>
            </tr>
            <tr>
                <th>Scanning</th>
                <td><?php echo $enabled === '1' ? 'Enabled (dashboard may scan this site)' : 'Disabled (dashboard scans are refused)'; ?></td>
            </tr>
        </table>
        <form method="post">
            <?php wp_nonce_field('saferwp_agent_settings'); ?>
            <button type="submit" name="saferwp_regenerate" class="button">Regenerate API key</button>
        </form>
    </div>
    <?php
}

/**
 * REST API surface consumed by the dashboard.
 */
add_action('rest_api_init', function () {
    register_rest_route('saferwp/v1', '/inventory', [
        'methods' => 'GET',
        'callback' => 'saferwp_agent_get_inventory',
        'permission_callback' => 'saferwp_agent_authenticate',
    ]);

    register_rest_route('saferwp/v1', '/scan-toggle', [
        'methods' => 'POST',
        'callback' => 'saferwp_agent_set_scan_enabled',
        'permission_callback' => 'saferwp_agent_authenticate',
    ]);
});

function saferwp_agent_authenticate(WP_REST_Request $request) {
    $provided = $request->get_header('x-saferwp-key');
    $expected = saferwp_agent_get_or_create_api_key();
    if (!$provided || !hash_equals($expected, $provided)) {
        return new WP_Error('saferwp_unauthorized', 'Invalid or missing API key', ['status' => 401]);
    }
    return true;
}

/**
 * Returns installed plugins/themes and versions. Uses WP core's own plugin/theme
 * APIs rather than parsing files directly, so it stays accurate across WP versions.
 */
function saferwp_agent_get_inventory(WP_REST_Request $request) {
    if (get_option(SAFERWP_AGENT_OPTION_ENABLED, '1') !== '1') {
        return new WP_Error('saferwp_scan_disabled', 'Scanning is disabled on this site', ['status' => 403]);
    }

    if (!function_exists('get_plugins')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }

    $all_plugins = get_plugins();
    $active_plugins = get_option('active_plugins', []);
    $plugins = [];
    foreach ($all_plugins as $path => $data) {
        $slug = strpos($path, '/') !== false ? dirname($path) : basename($path, '.php');
        $plugins[] = [
            'slug' => $slug,
            'name' => $data['Name'],
            'version' => $data['Version'],
            'active' => in_array($path, $active_plugins, true),
        ];
    }

    $themes = [];
    foreach (wp_get_themes() as $slug => $theme) {
        $themes[] = [
            'slug' => $slug,
            'name' => $theme->get('Name'),
            'version' => $theme->get('Version'),
            'active' => get_stylesheet() === $slug,
        ];
    }

    global $wp_version;

    return new WP_REST_Response([
        'site_url' => home_url(),
        'wp_version' => $wp_version,
        'plugins' => $plugins,
        'themes' => $themes,
        'generated_at' => gmdate('c'),
    ], 200);
}

function saferwp_agent_set_scan_enabled(WP_REST_Request $request) {
    $enabled = $request->get_param('enabled');
    update_option(SAFERWP_AGENT_OPTION_ENABLED, $enabled ? '1' : '0');
    return new WP_REST_Response(['enabled' => (bool) $enabled], 200);
}
