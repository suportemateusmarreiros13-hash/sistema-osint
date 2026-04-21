#!/usr/bin/env python
"""
Limpar banco de dados - Remove todos os scans antigos
"""

import os
import sys

# Adicionar backend ao path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from database import SessionLocal, ScanRecord, Base, engine

def clear_history():
    """Limpa todo o histórico de scans"""
    db = SessionLocal()
    try:
        # Contar scans antes
        count_before = db.query(ScanRecord).count()
        print(f"📊 Scans no banco antes: {count_before}")
        
        # Deletar todos
        db.query(ScanRecord).delete()
        db.commit()
        
        # Contar após
        count_after = db.query(ScanRecord).count()
        print(f"✅ Scans deletados: {count_before - count_after}")
        print(f"📊 Scans no banco agora: {count_after}")
        
    except Exception as e:
        print(f"❌ Erro ao limpar: {e}")
        db.rollback()
    finally:
        db.close()

def reset_database():
    """Reset completo do banco de dados (dropall + criar novamente)"""
    try:
        print("🗑️  Removendo todas as tabelas...")
        Base.metadata.drop_all(engine)
        
        print("🔨 Recriando tabelas...")
        Base.metadata.create_all(engine)
        
        print("✅ Banco de dados resetado com sucesso!")
    except Exception as e:
        print(f"❌ Erro ao resetar banco: {e}")

if __name__ == '__main__':
    print("="*50)
    print("🧹 LIMPEZA DE BANCO DE DADOS")
    print("="*50)
    
    if len(sys.argv) > 1 and sys.argv[1] == '--full':
        print("\n📌 Modo FULL RESET")
        reset_database()
    else:
        print("\n📌 Modo LIMPEZA (histórico)")
        clear_history()
    
    print("\n✅ Pronto!\n")
