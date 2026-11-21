<?php
declare(strict_types=1);
namespace Tests\Support\Identity;
use LogicException;
/** Test-only A/B model; never a PostgreSQL/RLS substitute or production service. */
final class StatefulTenantProbeOrchestrator {
 private array $rows=['A'=>['a1'=>'alpha'],'B'=>['b1'=>'bravo']]; private array $seen=[];
 public function __construct(private StatefulAuthorityAffinityTransport $transport,private string $runId){}
 public function execute(string $id,string $actor,string $tenant,string $generation,string $connection,string $tx,string $operation,string $target,?string $value=null,?string $bindConnection=null,?string $bindTransaction=null):array{
  if(isset($this->seen[$id])||$this->runId===''||$actor!==$tenant||!in_array($operation,['read','create','update','delete'],true))throw new LogicException('probe-rejected');$this->seen[$id]=true;
  $acquired=false;$primary=null;
  try {$this->transport->begin($connection,$tx,$tenant,$generation);$acquired=true;$this->transport->bind($bindConnection??$connection,$bindTransaction??$tx,$tenant,$generation,'member-'.$actor);if($target!==$tenant)throw new LogicException('cross-tenant-denied');if($operation==='read')$result=$this->rows[$tenant];elseif($operation==='create'){$this->rows[$tenant]['new']=$value??'value';$result=1;}elseif($operation==='update'){$this->rows[$tenant]['a1']=$value??'updated';$result=1;}else{unset($this->rows[$tenant]['a1']);$result=1;}$this->transport->write($tenant);return ['case_id'=>$id,'run_id'=>$this->runId,'actor'=>$actor,'tenant'=>$tenant,'operation'=>$operation,'result'=>$result];} catch(\Throwable $exception){$primary=$exception;throw $exception;} finally {if($acquired){try{$this->transport->resetOwned($connection,$tx);}catch(\Throwable $cleanup){$this->transport->events[]='cleanup-failed';if($primary===null)throw $cleanup;}}}
 }
 public function snapshot(string $tenant):array{return $this->rows[$tenant];}
}
