<?php
declare(strict_types=1);
namespace Tests\Unit\Modules\Identity\Application;
use LogicException;use Tests\Support\Identity\StatefulAuthorityAffinityTransport;use Tests\TestCase;
final class StatefulAuthorityAffinityTransportTest extends TestCase {
 public function test_c03_01_same_connection_binds_writes_and_resets():void{$t=new StatefulAuthorityAffinityTransport;$t->begin('c1','tx1','A','g1');$t->bind('c1','tx1','A','g1','m1');$t->write('A');$t->resetOwned('c1','tx1');self::assertSame(['begin','bind','write','reset'],$t->events);}
 public function test_c03_negatives():void{foreach(['cross','wrong-connection','wrong-generation','revoked'] as $kind){$t=new StatefulAuthorityAffinityTransport;$t->begin('c1','tx1','A','g1');if($kind==='revoked')$t->revoke('g1');try{if($kind==='cross'){$t->bind('c1','tx1','A','g1','m1');$t->write('B');}elseif($kind==='wrong-connection')$t->bind('c2','tx1','A','g1','m1');elseif($kind==='wrong-generation')$t->bind('c1','tx1','A','g2','m1');else $t->bind('c1','tx1','A','g1','m1');self::fail($kind.' accepted');}catch(LogicException){self::addToAssertionCount(1);}}}
}
