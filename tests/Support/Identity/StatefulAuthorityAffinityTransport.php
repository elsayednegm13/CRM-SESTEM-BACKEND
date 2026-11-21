<?php
declare(strict_types=1);
namespace Tests\Support\Identity;
use LogicException;
/** Offline model; it never represents PostgreSQL RLS evidence. */
final class StatefulAuthorityAffinityTransport {
 public array $events=[]; private ?array $tx=null; private ?array $bound=null; private array $revoked=[]; private bool $failNextReset=false;
 public function begin(string $connection,string $transaction,string $tenant,string $generation): void {if($this->tx!==null)throw new LogicException('nested');$this->tx=compact('connection','transaction','tenant','generation');$this->events[]='begin';}
 public function revoke(string $generation): void {$this->revoked[$generation]=true;$this->events[]='revoke';}
 public function bind(string $connection,string $transaction,string $tenant,string $generation,string $member): void {if($this->tx===null||$this->tx['connection']!==$connection||$this->tx['transaction']!==$transaction||$this->tx['tenant']!==$tenant||$this->tx['generation']!==$generation||isset($this->revoked[$generation])||$member==='')throw new LogicException('authority-affinity-rejected');$this->bound=compact('tenant','generation','member');$this->events[]='bind';}
 public function write(string $tenant): void {if($this->bound===null||$this->bound['tenant']!==$tenant)throw new LogicException('cross-tenant-denied');$this->events[]='write';}
 /** Releases only the transaction acquired by the current probe. */
 public function resetOwned(string $connection,string $transaction): void {if($this->tx===null||$this->tx['connection']!==$connection||$this->tx['transaction']!==$transaction)throw new LogicException('authority-affinity-cleanup-ownership-rejected');$this->bound=null;$this->tx=null;$this->events[]='reset';if($this->failNextReset){$this->failNextReset=false;throw new LogicException('authority-affinity-cleanup-failed');}}
 public function failNextReset(): void {$this->failNextReset=true;}
 /** @return array{transaction:?array,bound:?array} */
 public function state(): array{return ['transaction'=>$this->tx,'bound'=>$this->bound];}
}
