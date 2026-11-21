<?php

declare(strict_types=1);

use App\Modules\Tenancy\Application\SalesInput;
use App\Modules\Tenancy\Domain\CustomerInputException;

require_once __DIR__.'/../../../vendor/autoload.php';

/** @param callable():void $callback */
function w3rejects(callable $callback): void { try { $callback(); } catch (CustomerInputException) { return; } throw new RuntimeException('Expected W3 validation rejection.'); }
$uuid = '00000000-0000-4000-8000-000000000001';
$deal = SalesInput::deal(['title'=>'Launch','customer_id'=>$uuid,'pipeline_id'=>$uuid,'stage_id'=>$uuid,'value_amount'=>'123.4500','currency_code'=>'usd']);
if ($deal['currency_code'] !== 'USD' || $deal['value_amount'] !== '123.4500') throw new RuntimeException('Deal normalization failed.');
$task = SalesInput::task(['title'=>'Call','customer_id'=>$uuid,'priority'=>'HIGH','status'=>'TODO','due_at'=>'2026-11-06T10:00:00+02:00']);
if ($task['deal_id'] !== null || $task['due_at'] === null) throw new RuntimeException('Task normalization failed.');
w3rejects(fn()=>SalesInput::deal(['title'=>'Bad','customer_id'=>$uuid,'pipeline_id'=>$uuid,'stage_id'=>$uuid,'value_amount'=>'1e3','currency_code'=>'USD']));
w3rejects(fn()=>SalesInput::task(['title'=>'Bad','customer_id'=>$uuid,'deal_id'=>$uuid]));
w3rejects(fn()=>SalesInput::transition(['from_stage_id'=>$uuid,'to_stage_id'=>$uuid,'version'=>0]));
$root=dirname(__DIR__,3); $routes=(string)file_get_contents($root.'/routes/api.php'); $migration=(string)file_get_contents($root.'/database/migrations/2026_11_06_000069_create_w3_sales_and_activities.php'); $activity=(string)file_get_contents($root.'/app/Modules/Tenancy/Http/Controllers/SalesActivityController.php');
foreach (["Route::post('/deals'", "Route::patch('/deals/{deal}'", "Route::post('/deals/{deal}/transition'", "Route::get('/activities'", "Route::post('/tasks'", "Route::post('/tasks/{task}/complete'", "Route::post('/pipelines'"] as $needle) if(!str_contains($routes,$needle))throw new RuntimeException('Missing W3 route.');
foreach (['sales_pipelines','sales_pipeline_stages','deal_stage_transitions','sales_tasks','sales_activities','FORCE ROW LEVEL SECURITY','REVOKE ALL ON TABLE','deals.manage','tasks.manage'] as $needle) if(!str_contains($migration,$needle))throw new RuntimeException('Missing W3 schema safety contract.');
foreach (["activities.view", "where('tenant_id',\$actor->tenantId)", "customer_id", "deal_id", "orderByDesc('occurred_at')", "actor_present"] as $needle) if(!str_contains($activity,$needle))throw new RuntimeException('Missing W3 activity boundary contract.');
echo "W3_SOURCE_ONLY_TEST=PASS\n";
